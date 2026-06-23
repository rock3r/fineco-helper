//! `fineco-query` — the store-query worker behind the snapshot-query socket.
//!
//! Answers the cached-read [`fineco_ipc::Request`] commands from the local
//! SQLite store. It holds the DB handle and the freshness policy; the
//! internet-facing gateway never depends on this crate — it reaches these reads
//! only over the socket, so the "gateway never reads the DB directly" invariant
//! is structural.

use fineco_core::SafeError;
use fineco_ipc::{
    AllocationHistoryDto, AllocationPointDto, FreshnessDto, FreshnessReportDto, FullSnapshotDto,
    HistoryParams, MovementDto, MovementsDto, OWNER_AUTH_ID, OrderDto, OrdersDto, Policy,
    PortfolioHistoryDto, PortfolioHistoryPointDto, PortfolioSummaryDto, PositionDto,
    PositionHistoryDto, PositionHistoryParams, PositionHistoryPointDto, Request, ResponseBody,
    ShareableReportDto, ShareableRowDto, TaxCarryForwardDto, TaxCarryForwardListDto, TaxMinusDto,
    TaxMinusListDto,
};
use fineco_store::{
    AllocationPoint, PortfolioSnapshotRow, PositionHistoryPoint, PositionRow, ShareableRow, Store,
};

/// Per-area maximum age (seconds) beyond which cached data is reported `stale`.
#[derive(Debug, Clone, Copy)]
pub struct FreshnessMaxAge {
    pub portfolio: i64,
    pub orders: i64,
    pub tax: i64,
    pub movements: i64,
}

impl Default for FreshnessMaxAge {
    fn default() -> Self {
        // Conservative defaults; the worker config can override these.
        Self {
            portfolio: 24 * 3600,
            orders: 24 * 3600,
            tax: 7 * 24 * 3600,
            movements: 24 * 3600,
        }
    }
}

/// Answers cached-read commands from the store. Holds the DB handle; queries are
/// read-only. Enforces the capability policy independently of the gateway (plan
/// "Capability Model": the worker must validate capabilities on its own).
pub struct QueryHandler {
    store: Store,
    max_age: FreshnessMaxAge,
    policy: Policy,
}

impl QueryHandler {
    /// Build a handler over `store` with the given freshness and capability
    /// policies. The capability policy is enforced on every request; the worker
    /// trusts no `auth_id` from the wire and checks the single owner identity.
    #[must_use]
    pub fn new(store: Store, max_age: FreshnessMaxAge, policy: Policy) -> Self {
        Self {
            store,
            max_age,
            policy,
        }
    }

    /// Answer one validated request as of `now_epoch` (Unix seconds). The caller
    /// supplies the clock so the mapping is deterministic in tests.
    ///
    /// # Errors
    /// A [`SafeError`] envelope: `invalid_request` if the policy does not permit
    /// the command or it is not yet served, or `internal` on a storage failure
    /// (the raw cause is never surfaced).
    pub fn handle(&self, request: Request, now_epoch: i64) -> Result<ResponseBody, SafeError> {
        // Independent capability enforcement (defense in depth behind the
        // gateway's own check). Fail closed for any ungranted capability.
        if !self
            .policy
            .allows(OWNER_AUTH_ID, request.required_capability())
        {
            return Err(SafeError::invalid_request(
                "the configured policy does not permit this command.",
            ));
        }
        match request {
            Request::PortfolioGetFreshness => Ok(ResponseBody::Freshness(FreshnessReportDto {
                portfolio: self.freshness("portfolio", self.max_age.portfolio, now_epoch)?,
                orders: self.freshness("orders", self.max_age.orders, now_epoch)?,
                tax: self.freshness("tax", self.max_age.tax, now_epoch)?,
                movements: self.freshness("movements", self.max_age.movements, now_epoch)?,
            })),
            Request::OrdersGetLatestMonitor => self.latest_orders(),
            Request::TaxGetLatestCarryForward => self.latest_tax_carry_forward(),
            Request::TaxGetLatestMinusByYear => self.latest_tax_minus_by_year(),
            Request::MovementsGetLatest => self.latest_movements(),
            Request::PortfolioGetLatestSnapshotSummary => self.latest_summary(),
            Request::PortfolioGetLatestFullSnapshot => self.latest_full_snapshot(),
            Request::PortfolioGetLatestShareableReport => self.latest_shareable_report(),
            Request::PortfolioGetHistory(params) => self.portfolio_history(params),
            Request::PortfolioGetAllocationHistory => self.allocation_history(),
            Request::PortfolioGetPositionHistory(params) => self.position_history(params),
            // Market tools (ETF/enrichment) are served by the gateway in-process
            // via the credential-free market path, not this store worker.
            _ => Err(SafeError::invalid_request("Command not yet supported.")),
        }
    }

    /// The latest order-monitor capture as a wire DTO.
    fn latest_orders(&self) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .latest_orders()
            .map_err(|_| SafeError::internal())?;
        // Source the timestamp from the capture marker, not the rows, so a
        // legitimately empty latest capture still reports its own `captured_at`.
        let captured_at = self
            .store
            .latest_capture_at("orders")
            .map_err(|_| SafeError::internal())?;
        let orders = rows
            .into_iter()
            .map(|row| OrderDto {
                trans_id_hash: row.trans_id_hash,
                instr_id: row.asset_instr_id,
                venue_system: row.asset_venue_system,
                status: row.status,
                sign: row.sign,
                order_size: row.order_size,
                size_filled: row.size_filled,
                avg_price: row.avg_price,
                submit_time: row.submit_time,
            })
            .collect();
        Ok(ResponseBody::Orders(OrdersDto {
            captured_at,
            orders,
        }))
    }

    /// The latest tax carry-forward capture as a wire DTO.
    fn latest_tax_carry_forward(&self) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .latest_tax_carry_forward()
            .map_err(|_| SafeError::internal())?;
        let captured_at = self
            .store
            .latest_capture_at("tax")
            .map_err(|_| SafeError::internal())?;
        let entries = rows
            .into_iter()
            .map(|row| TaxCarryForwardDto {
                date_from: row.date_from,
                date_to: row.date_to,
                total: row.total,
            })
            .collect();
        Ok(ResponseBody::TaxCarryForward(TaxCarryForwardListDto {
            captured_at,
            entries,
        }))
    }

    /// The latest tax minus-by-year capture as a wire DTO.
    fn latest_tax_minus_by_year(&self) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .latest_tax_minus_by_year()
            .map_err(|_| SafeError::internal())?;
        let captured_at = self
            .store
            .latest_capture_at("tax")
            .map_err(|_| SafeError::internal())?;
        let entries = rows
            .into_iter()
            .map(|row| TaxMinusDto {
                year: row.year,
                minus_residue: row.minus_residue,
                expiration_date: row.expiration_date,
            })
            .collect();
        Ok(ResponseBody::TaxMinus(TaxMinusListDto {
            captured_at,
            entries,
        }))
    }

    /// The latest bank account movements capture as a wire DTO.
    fn latest_movements(&self) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .latest_movements()
            .map_err(|_| SafeError::internal())?;
        let captured_at = self
            .store
            .latest_capture_at("movements")
            .map_err(|_| SafeError::internal())?;
        let movements = rows
            .into_iter()
            .map(|row| MovementDto {
                movement_id_hash: row.movement_id_hash,
                causale: row.causale,
                descrizione: row.descrizione,
                descrizione_breve: row.descrizione_breve,
                importo: row.importo,
                tipo_movimento: row.tipo_movimento,
                data_operazione: row.data_operazione,
                data_registrazione: row.data_registrazione,
                data_valuta: row.data_valuta,
                causale_movimento: row.causale_movimento,
                categoria_id: row.categoria_id,
                sottocategoria_id: row.sottocategoria_id,
            })
            .collect();
        Ok(ResponseBody::Movements(MovementsDto {
            captured_at,
            movements,
        }))
    }

    /// The latest portfolio snapshot's totals as a wire DTO.
    fn latest_summary(&self) -> Result<ResponseBody, SafeError> {
        let snapshot = self
            .store
            .latest_portfolio_snapshot()
            .map_err(|_| SafeError::internal())?;
        Ok(ResponseBody::PortfolioSummary(summary_dto(
            snapshot.as_ref(),
        )))
    }

    /// The latest full snapshot (totals + every position).
    fn latest_full_snapshot(&self) -> Result<ResponseBody, SafeError> {
        let snapshot = self
            .store
            .latest_portfolio_snapshot()
            .map_err(|_| SafeError::internal())?;
        let positions = match &snapshot {
            Some(row) => self
                .store
                .positions_for_snapshot(row.id)
                .map_err(|_| SafeError::internal())?,
            None => Vec::new(),
        };
        Ok(ResponseBody::PortfolioFullSnapshot(FullSnapshotDto {
            summary: summary_dto(snapshot.as_ref()),
            positions: positions.into_iter().map(position_dto).collect(),
        }))
    }

    /// The latest shareable report (identity + weights + percentages only).
    fn latest_shareable_report(&self) -> Result<ResponseBody, SafeError> {
        let snapshot = self
            .store
            .latest_portfolio_snapshot()
            .map_err(|_| SafeError::internal())?;
        let (captured_at, rows) = match snapshot {
            Some(row) => {
                let rows = self
                    .store
                    .shareable_report_rows(row.id)
                    .map_err(|_| SafeError::internal())?;
                (Some(row.captured_at), rows)
            }
            None => (None, Vec::new()),
        };
        Ok(ResponseBody::PortfolioShareableReport(ShareableReportDto {
            captured_at,
            rows: rows.into_iter().map(shareable_row_dto).collect(),
        }))
    }

    /// Recent portfolio snapshot totals (chronological, oldest first).
    fn portfolio_history(&self, params: HistoryParams) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .portfolio_history(params.limit)
            .map_err(|_| SafeError::internal())?;
        Ok(ResponseBody::PortfolioHistory(PortfolioHistoryDto {
            points: rows.into_iter().map(history_point_dto).collect(),
        }))
    }

    /// Per-instrument allocation weights across snapshots (oldest first).
    fn allocation_history(&self) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .allocation_history(fineco_store::MAX_HISTORY_SNAPSHOTS)
            .map_err(|_| SafeError::internal())?;
        Ok(ResponseBody::AllocationHistory(AllocationHistoryDto {
            points: rows.into_iter().map(allocation_point_dto).collect(),
        }))
    }

    /// One instrument's history across snapshots (oldest first).
    fn position_history(&self, params: PositionHistoryParams) -> Result<ResponseBody, SafeError> {
        let rows = self
            .store
            .position_history(
                &params.instr_id,
                &params.venue_system,
                fineco_store::MAX_HISTORY_SNAPSHOTS,
            )
            .map_err(|_| SafeError::internal())?;
        Ok(ResponseBody::PositionHistory(PositionHistoryDto {
            points: rows.into_iter().map(position_history_point_dto).collect(),
        }))
    }

    /// Freshness of one data area as a wire DTO.
    fn freshness(
        &self,
        data_area: &str,
        max_age_seconds: i64,
        now_epoch: i64,
    ) -> Result<FreshnessDto, SafeError> {
        let freshness = self
            .store
            .freshness_for(data_area, now_epoch, max_age_seconds)
            .map_err(|_| SafeError::internal())?;
        Ok(FreshnessDto {
            state: freshness.state.as_str().to_string(),
            captured_at: freshness.captured_at,
        })
    }
}

/// Map an optional snapshot row to the summary DTO (all `None` if absent).
fn summary_dto(snapshot: Option<&PortfolioSnapshotRow>) -> PortfolioSummaryDto {
    match snapshot {
        Some(row) => PortfolioSummaryDto {
            captured_at: Some(row.captured_at.clone()),
            source: Some(row.source.clone()),
            market_value: row.market_value,
            book_value: row.book_value,
            profit_loss: row.profit_loss,
            profit_loss_perc: row.profit_loss_perc,
        },
        None => PortfolioSummaryDto {
            captured_at: None,
            source: None,
            market_value: None,
            book_value: None,
            profit_loss: None,
            profit_loss_perc: None,
        },
    }
}

fn position_dto(row: PositionRow) -> PositionDto {
    PositionDto {
        instr_id: row.asset_instr_id,
        venue_system: row.asset_venue_system,
        symbol: row.symbol,
        qty: row.qty,
        avg_price: row.avg_price,
        market_price: row.market_price,
        book_value: row.book_value,
        market_value: row.market_value,
        profit_loss: row.profit_loss,
        profit_loss_perc: row.profit_loss_perc,
        weight_perc: row.weight_perc,
    }
}

fn history_point_dto(row: PortfolioSnapshotRow) -> PortfolioHistoryPointDto {
    PortfolioHistoryPointDto {
        captured_at: row.captured_at,
        market_value: row.market_value,
        book_value: row.book_value,
        profit_loss: row.profit_loss,
        profit_loss_perc: row.profit_loss_perc,
    }
}

fn allocation_point_dto(point: AllocationPoint) -> AllocationPointDto {
    AllocationPointDto {
        captured_at: point.captured_at,
        instr_id: point.instr_id,
        venue_system: point.venue_system,
        symbol: point.symbol,
        weight_perc: point.weight_perc,
    }
}

fn position_history_point_dto(point: PositionHistoryPoint) -> PositionHistoryPointDto {
    PositionHistoryPointDto {
        captured_at: point.captured_at,
        weight_perc: point.weight_perc,
        profit_loss_perc: point.profit_loss_perc,
        market_value: point.market_value,
    }
}

fn shareable_row_dto(row: ShareableRow) -> ShareableRowDto {
    ShareableRowDto {
        description: row.description,
        symbol: row.symbol,
        instr_id: row.instr_id,
        venue_system: row.venue_system,
        kind: row.kind,
        currency: row.currency,
        weight_perc: row.weight_perc,
        profit_loss_perc: row.profit_loss_perc,
    }
}
