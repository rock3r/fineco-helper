//! Tests for the pure enrichment core: parse-not-execute extraction, the source
//! allowlist, bounded output, and ISIN verification. Fixtures are SYNTHETIC and use
//! a fake host — never the real enrichment host.

use fineco_market::{EnrichmentHostAllowlist, build_enrichment_report, validate_source_url};

const NOW: &str = "2026-06-03T12:00:00Z";
const SOURCE: &str = "https://stocks.example/stocks/it/diversified-financials/syn-tip/synth-shares";

/// Wrap a `__REACT_QUERY_STATE__` payload in a minimal HTML page.
fn page(payload: &str) -> String {
    format!(
        "<html><head><script>window.__REACT_QUERY_STATE__ = {payload};</script></head><body>SYNTHETIC</body></html>"
    )
}

/// A canonical synthetic company cache, with one JS-ism (`undefined`) and a
/// string that literally contains the word "undefined" (must be preserved).
fn canonical_payload() -> String {
    r#"{
      "queries": [
        {
          "queryKey": ["company", "synth"],
          "state": {
            "data": {
              "data": {
                "name": "Fallback Name",
                "unique_symbol": "BIT:TIP",
                "exchange_symbol": "BIT",
                "isin_symbol": "IT0003153621",
                "year_founded": undefined,
                "info": { "name": "fallback info" },
                "analysis": {
                  "data": {
                    "extended": {
                      "data": {
                        "raw_data": {
                          "data": {
                            "company_info": {
                              "name": "SYNTHETIC Tamburi Investment Partners SpA",
                              "unique_symbol": "BIT:TIP",
                              "exchange_symbol": "BIT",
                              "isin_symbol": "IT0003153621",
                              "country": "Italy",
                              "url": "https://www.tamburi.example",
                              "description": "SYNTHETIC holding; the value is undefined here."
                            }
                          }
                        },
                        "analysis": {
                          "value": { "pe": 12.3, "trap": "1);DROP TABLE;--" },
                          "future": { "growth": 0.05 },
                          "past": {},
                          "health": {},
                          "dividend": {},
                          "management": {}
                        },
                        "scores": { "value": 4, "future": 3, "total": 20 }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }"#
    .to_string()
}

#[test]
fn extracts_company_scores_and_metrics() {
    let report = build_enrichment_report(&page(&canonical_payload()), SOURCE, NOW, None)
        .expect("report should build");

    assert_eq!(report.captured_at, NOW);
    assert_eq!(report.source_url, SOURCE);

    // company_info wins over the top-level fallbacks.
    assert_eq!(
        report.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(report.company.ticker, "BIT:TIP");
    assert_eq!(report.company.exchange, "BIT");
    assert_eq!(report.company.isin, "IT0003153621");
    assert_eq!(report.company.country, "Italy");
    assert_eq!(report.company.website, "https://www.tamburi.example");
    assert!(report.company.description.contains("SYNTHETIC"));
    // A string literally containing "undefined" is preserved, not nulled.
    assert!(report.company.description.contains("undefined"));

    assert_eq!(report.scores["value"], serde_json::json!(4));
    assert_eq!(report.scores["total"], serde_json::json!(20));
    assert_eq!(report.metrics["value"]["pe"], serde_json::json!(12.3));
    assert_eq!(report.metrics["future"]["growth"], serde_json::json!(0.05));
}

#[test]
fn extracts_fund_scores_and_metrics_from_etf_pages() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "vhyl"],
          "state": {
            "data": {
              "data": {
                "name": "Fallback ETF Name",
                "unique_symbol": "LSE:VHYL",
                "exchange_symbol": "LSE",
                "isin_symbol": "IE00B8GKDB10",
                "analysis": {
                  "data": {
                    "extended": {
                      "data": {
                        "raw_data": {
                          "data": {
                            "fund_info": {
                              "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                              "unique_symbol": "LSE:VHYL",
                              "exchange_symbol": "LSE",
                              "isin_symbol": "IE00B8GKDB10",
                              "country": "Ireland",
                              "url": "https://www.vanguard.example",
                              "description": "Synthetic ETF profile."
                            }
                          }
                        },
                        "analysis": {
                          "value": { "expense_ratio": 0.0029 },
                          "future": {},
                          "past": {},
                          "health": {},
                          "dividend": { "yield": 0.037 },
                          "management": {}
                        },
                        "scores": { "value": 3, "dividend": 5, "total": 16 }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, Some("IE00B8GKDB10"))
        .expect("fund-style ETF report should build");

    assert_eq!(
        report.company.name,
        "Vanguard FTSE All-World High Dividend Yield UCITS ETF"
    );
    assert_eq!(report.company.ticker, "LSE:VHYL");
    assert_eq!(report.company.isin, "IE00B8GKDB10");
    assert_eq!(report.company.country, "Ireland");
    assert_eq!(
        report.metrics["value"]["expense_ratio"],
        serde_json::json!(0.0029)
    );
    assert_eq!(
        report.metrics["dividend"]["yield"],
        serde_json::json!(0.037)
    );
    assert_eq!(report.scores["total"], serde_json::json!(16));
}

#[test]
fn skips_empty_raw_info_entries_for_fund_pages() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "vhyl"],
          "state": {
            "data": {
              "data": {
                "analysis": {
                  "data": {
                    "extended": {
                      "data": {
                        "raw_data": {
                          "data": {
                            "company_info": {},
                            "fund_info": {
                              "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                              "unique_symbol": "LSE:VHYL",
                              "exchange_symbol": "LSE",
                              "isin_symbol": "IE00B8GKDB10"
                            }
                          }
                        },
                        "analysis": {},
                        "scores": {}
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("fund info should not be shadowed by empty company info");

    assert_eq!(
        report.company.name,
        "Vanguard FTSE All-World High Dividend Yield UCITS ETF"
    );
    assert_eq!(report.company.ticker, "LSE:VHYL");
}

#[test]
fn sparse_company_info_does_not_shadow_richer_fund_info() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "vhyl"],
          "state": {
            "data": {
              "data": {
                "analysis": {
                  "data": {
                    "extended": {
                      "data": {
                        "raw_data": {
                          "data": {
                            "company_info": {
                              "unique_symbol": "LSE:PLACEHOLDER"
                            },
                            "fund_info": {
                              "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                              "unique_symbol": "LSE:VHYL",
                              "exchange_symbol": "LSE",
                              "isin_symbol": "IE00B8GKDB10",
                              "country": "Ireland",
                              "url": "https://www.vanguard.example",
                              "description": "Synthetic ETF profile."
                            }
                          }
                        },
                        "analysis": {},
                        "scores": {}
                      }
                    }
                  }
                }
              }
            }
          }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("sparse placeholder should not shadow fund info");

    assert_eq!(
        report.company.name,
        "Vanguard FTSE All-World High Dividend Yield UCITS ETF"
    );
    assert_eq!(report.company.ticker, "LSE:VHYL");
    assert_eq!(report.company.country, "Ireland");
}

#[test]
fn fund_profile_prefers_fund_info_over_populated_company_info() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "global-income"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": {
                "company_info": {
                  "name": "Global Asset Manager plc",
                  "unique_symbol": "LSE:GAM",
                  "exchange_symbol": "LSE",
                  "isin_symbol": "GB0000000001",
                  "country": "United Kingdom",
                  "url": "https://manager.example",
                  "description": "Synthetic manager profile."
                },
                "fund_info": {
                  "name": "Global Income UCITS ETF",
                  "unique_symbol": "LSE:GINC",
                  "isin_symbol": "IE00B8GKDB10"
                }
              } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("fund profile should prefer fund metadata");

    assert_eq!(report.company.name, "Global Income UCITS ETF");
    assert_eq!(report.company.ticker, "LSE:GINC");
    assert_eq!(report.company.isin, "IE00B8GKDB10");
    assert_eq!(report.company.country, "");
    assert_eq!(report.company.website, "");
    assert_eq!(report.company.description, "");
}

#[test]
fn company_profile_ignores_stale_fund_info() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "tip"],
          "state": { "data": { "data": {
            "name": "Fallback Company Name",
            "unique_symbol": "BIT:FALLBACK",
            "info": {
              "name": "Info Company Name",
              "unique_symbol": "BIT:INFO"
            },
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Stale Fund Profile",
                "unique_symbol": "LSE:OLD"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("company profile should ignore stale fund info");

    assert_eq!(report.company.name, "Info Company Name");
    assert_eq!(report.company.ticker, "BIT:INFO");
}

#[test]
fn selects_the_profile_that_matches_expected_isin() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Unrelated Company plc",
            "unique_symbol": "LSE:OLD",
            "isin_symbol": "GB0000000000",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": { "name": "Unrelated Company plc" } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "vhyl"],
          "state": { "data": { "data": {
            "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
            "unique_symbol": "LSE:VHYL",
            "isin_symbol": "IE00B8GKDB10",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                "unique_symbol": "LSE:VHYL",
                "isin_symbol": "IE00B8GKDB10"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, Some("IE00B8GKDB10"))
        .expect("expected ISIN should select the matching fund profile");

    assert_eq!(report.company.ticker, "LSE:VHYL");
}

#[test]
fn skips_unusable_company_profile_without_expected_isin() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "placeholder"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {} } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "vhyl"],
          "state": { "data": { "data": {
            "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
            "unique_symbol": "LSE:VHYL",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                "unique_symbol": "LSE:VHYL"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("usable fund profile should win over empty company profile");

    assert_eq!(report.company.ticker, "LSE:VHYL");
}

#[test]
fn preserves_react_query_order_when_no_expected_isin_is_supplied() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "vhyl"],
          "state": { "data": { "data": {
            "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
            "unique_symbol": "LSE:VHYL",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                "unique_symbol": "LSE:VHYL"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Unrelated Company plc",
            "unique_symbol": "LSE:OLD",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Unrelated Company plc",
                "unique_symbol": "LSE:OLD"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("source-order fund profile should be selected");

    assert_eq!(report.company.ticker, "LSE:VHYL");
}

#[test]
fn metadata_only_company_profile_does_not_shadow_usable_fund_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "country": "United Kingdom"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "vhyl"],
          "state": { "data": { "data": {
            "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
            "unique_symbol": "LSE:VHYL",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                "unique_symbol": "LSE:VHYL"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("metadata-only stale company profile should not shadow usable fund profile");

    assert_eq!(report.company.ticker, "LSE:VHYL");
}

#[test]
fn fund_profile_merges_split_raw_metadata_fields() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "vhyl"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": {
                "fund_info": {
                  "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                  "unique_symbol": "LSE:VHYL",
                  "isin_symbol": "IE00B8GKDB10"
                },
                "asset_info": {
                  "country": "Ireland",
                  "url": "https://www.vanguard.example",
                  "description": "Synthetic split ETF metadata."
                }
              } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("split raw metadata should be merged field by field");

    assert_eq!(
        report.company.name,
        "Vanguard FTSE All-World High Dividend Yield UCITS ETF"
    );
    assert_eq!(report.company.ticker, "LSE:VHYL");
    assert_eq!(report.company.country, "Ireland");
    assert_eq!(report.company.website, "https://www.vanguard.example");
    assert_eq!(report.company.description, "Synthetic split ETF metadata.");
}

#[test]
fn fund_profile_prefers_richer_raw_metadata_object() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "income"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": {
                "fund_info": {
                  "name": "Placeholder Income Fund"
                },
                "asset_info": {
                  "name": "Global Income UCITS ETF",
                  "unique_symbol": "LSE:GINC",
                  "exchange_symbol": "LSE",
                  "isin_symbol": "IE00SYNTH001",
                  "country": "Ireland",
                  "url": "https://www.example.com/global-income",
                  "description": "Richer synthetic ETF metadata."
                }
              } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("richer raw metadata object should be preferred");

    assert_eq!(report.company.name, "Global Income UCITS ETF");
    assert_eq!(report.company.ticker, "LSE:GINC");
    assert_eq!(report.company.exchange, "LSE");
    assert_eq!(report.company.isin, "IE00SYNTH001");
    assert_eq!(report.company.country, "Ireland");
    assert_eq!(
        report.company.website,
        "https://www.example.com/global-income"
    );
    assert_eq!(report.company.description, "Richer synthetic ETF metadata.");
}

#[test]
fn preserves_react_query_order_for_similar_profiles_without_expected_isin() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "current"],
          "state": { "data": { "data": {
            "name": "Global Income Fund",
            "unique_symbol": "LSE:GINC",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Global Income Fund",
                "unique_symbol": "LSE:GINC"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Global Income Holdings plc",
            "unique_symbol": "LSE:GLOB",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Global Income Holdings plc",
                "unique_symbol": "LSE:GLOB"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("source-order profile should win without expected ISIN");

    assert_eq!(report.company.ticker, "LSE:GINC");
}

#[test]
fn generic_name_overlap_does_not_replace_the_first_usable_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "current"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Global Income UCITS ETF",
                "unique_symbol": "LSE:GINC"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Global Income Fund",
            "unique_symbol": "LSE:OLD",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Global Income Fund",
                "unique_symbol": "LSE:OLD"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("generic overlap should not switch profiles without expected ISIN");

    assert_eq!(report.company.ticker, "LSE:GINC");
}

#[test]
fn short_exact_name_does_not_replace_a_more_specific_first_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "current"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Global Income UCITS ETF",
                "unique_symbol": "LSE:GINC"
              } } },
              "analysis": { "dividend": { "yield": 0.04 } },
              "scores": { "total": 17 }
            } } } }
          } } }
        },
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Global Income",
            "unique_symbol": "LSE:OLD",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Global Income",
                "unique_symbol": "LSE:OLD"
              } } },
              "analysis": { "value": { "pe": 10 } },
              "scores": { "total": 8 }
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("source order should keep the more specific first profile");

    assert_eq!(report.company.ticker, "LSE:GINC");
    assert_eq!(report.scores["total"], serde_json::json!(17));
}

#[test]
fn expected_isin_can_replace_a_stale_first_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Vanguard Group plc",
            "unique_symbol": "LSE:OLD",
            "isin_symbol": "GB0000000000",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Vanguard Group plc",
                "unique_symbol": "LSE:OLD",
                "isin_symbol": "GB0000000000"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "current"],
          "state": { "data": { "data": {
            "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
            "unique_symbol": "LSE:VHYL",
            "isin_symbol": "IE00B8GKDB10",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Vanguard FTSE All-World High Dividend Yield UCITS ETF",
                "unique_symbol": "LSE:VHYL",
                "isin_symbol": "IE00B8GKDB10"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, Some("IE00B8GKDB10"))
        .expect("expected ISIN should replace stale first profile");

    assert_eq!(report.company.ticker, "LSE:VHYL");
}

#[test]
fn metadata_only_profile_does_not_shadow_later_analysis_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "lightweight"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:LIGHT"
          } } }
        },
        {
          "queryKey": ["fund", "full"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Global Income UCITS ETF",
                "unique_symbol": "LSE:GINC"
              } } },
              "analysis": { "dividend": { "yield": 0.04 } },
              "scores": { "total": 17 }
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("full analysis profile should win over metadata-only cache entry");

    assert_eq!(report.company.ticker, "LSE:GINC");
    assert_eq!(report.scores["total"], serde_json::json!(17));
}

#[test]
fn exact_metadata_name_does_not_shadow_matching_analysis_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "full"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF USD Distributing Accumulating Hedged Class",
            "unique_symbol": "LSE:GINC",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Global Income UCITS ETF USD Distributing Accumulating Hedged Class",
                "unique_symbol": "LSE:GINC"
              } } },
              "analysis": { "dividend": { "yield": 0.04 } },
              "scores": { "total": 17 }
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "lightweight"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC"
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("matching full analysis profile should win over exact metadata shell");

    assert_eq!(
        report.company.name,
        "Global Income UCITS ETF USD Distributing Accumulating Hedged Class"
    );
    assert_eq!(report.company.ticker, "LSE:GINC");
    assert_eq!(report.scores["total"], serde_json::json!(17));
}

#[test]
fn expected_isin_metadata_profile_can_beat_stale_analysis_profile() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["fund", "lightweight"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC",
            "isin_symbol": "IE00GINC0001"
          } } }
        },
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Unrelated Company plc",
            "unique_symbol": "LSE:OLD",
            "isin_symbol": "GB0000000000",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Unrelated Company plc",
                "unique_symbol": "LSE:OLD",
                "isin_symbol": "GB0000000000"
              } } },
              "analysis": { "value": { "pe": 10 } },
              "scores": { "total": 8 }
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, Some("IE00GINC0001"))
        .expect("expected ISIN metadata profile should beat stale analysis shell");

    assert_eq!(report.company.ticker, "LSE:GINC");
    assert!(report.scores.as_object().expect("scores object").is_empty());
}

#[test]
fn expected_isin_metadata_profile_beats_generic_analysis_match() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "stale"],
          "state": { "data": { "data": {
            "name": "Global Income",
            "unique_symbol": "LSE:OLD",
            "isin_symbol": "GB0000000000",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "Global Income",
                "unique_symbol": "LSE:OLD",
                "isin_symbol": "GB0000000000"
              } } },
              "analysis": { "value": { "pe": 10 } },
              "scores": { "total": 8 }
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "lightweight"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC",
            "isin_symbol": "IE00GINC0001"
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, Some("IE00GINC0001"))
        .expect("expected ISIN metadata profile should beat generic analysis match");

    assert_eq!(report.company.ticker, "LSE:GINC");
    assert!(report.scores.as_object().expect("scores object").is_empty());
}

#[test]
fn blank_expected_isin_preserves_first_usable_profile_selection() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "tip"],
          "state": { "data": { "data": {
            "name": "SYNTHETIC Tamburi Investment Partners SpA",
            "unique_symbol": "BIT:TIP",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "name": "SYNTHETIC Tamburi Investment Partners SpA",
                "unique_symbol": "BIT:TIP"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "stale"],
          "state": { "data": { "data": {
            "name": "Unrelated Fund",
            "unique_symbol": "LSE:OLD",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "fund_info": {
                "name": "Unrelated Fund",
                "unique_symbol": "LSE:OLD"
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, Some("   "))
        .expect("blank expected ISIN should behave like no expected ISIN for profile selection");

    assert_eq!(report.company.ticker, "BIT:TIP");
}

#[test]
fn no_expected_isin_falls_back_to_usable_metadata_after_empty_analysis_shell() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "stale-analysis"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": {} },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        },
        {
          "queryKey": ["fund", "metadata"],
          "state": { "data": { "data": {
            "name": "Global Income UCITS ETF",
            "unique_symbol": "LSE:GINC"
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("usable metadata profile should win when analysis shells are empty");

    assert_eq!(report.company.name, "Global Income UCITS ETF");
    assert_eq!(report.company.ticker, "LSE:GINC");
}

#[test]
fn partial_recognized_profile_builds_a_warning_report() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "partial"],
          "state": { "data": { "data": {
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": {} },
              "analysis": { "value": { "pe": 12.3 } },
              "scores": { "value": 4 }
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("partial recognized profile should still return a bounded report");

    assert_eq!(report.company.name, "");
    assert_eq!(report.metrics["value"]["pe"], serde_json::json!(12.3));
    assert_eq!(report.scores["value"], serde_json::json!(4));
    assert!(
        report
            .warnings
            .iter()
            .any(|item| item == "Missing company name.")
    );
}

#[test]
fn metadata_only_raw_info_augments_profile_root_display_fields() {
    let payload = r#"{
      "queries": [
        {
          "queryKey": ["company", "tip"],
          "state": { "data": { "data": {
            "name": "SYNTHETIC Tamburi Investment Partners SpA",
            "unique_symbol": "BIT:TIP",
            "exchange_symbol": "BIT",
            "isin_symbol": "IT0003153621",
            "analysis": { "data": { "extended": { "data": {
              "raw_data": { "data": { "company_info": {
                "country": "Italy",
                "url": "https://www.tamburi.example",
                "description": "Synthetic metadata-only raw profile."
              } } },
              "analysis": {},
              "scores": {}
            } } } }
          } } }
        }
      ]
    }"#;

    let report = build_enrichment_report(&page(payload), SOURCE, NOW, None)
        .expect("metadata-only raw info should augment root display fields");

    assert_eq!(
        report.company.name,
        "SYNTHETIC Tamburi Investment Partners SpA"
    );
    assert_eq!(report.company.ticker, "BIT:TIP");
    assert_eq!(report.company.country, "Italy");
    assert_eq!(report.company.website, "https://www.tamburi.example");
    assert_eq!(
        report.company.description,
        "Synthetic metadata-only raw profile."
    );
}

#[test]
fn parse_is_data_only_not_execution() {
    // A metric value that looks like injected code is kept verbatim as data —
    // never interpreted. (Reaching this assertion at all means nothing ran it.)
    let report = build_enrichment_report(&page(&canonical_payload()), SOURCE, NOW, None)
        .expect("report should build");
    assert_eq!(
        report.metrics["value"]["trap"],
        serde_json::json!("1);DROP TABLE;--")
    );
}

#[test]
fn bare_undefined_becomes_absent_not_an_error() {
    // `year_founded: undefined` must normalize cleanly (no parse failure). It is
    // not a surfaced field, so we just assert the report builds.
    let report = build_enrichment_report(&page(&canonical_payload()), SOURCE, NOW, None);
    assert!(report.is_ok());
}

#[test]
fn missing_marker_is_a_safe_error() {
    let html = "<html><body>no embedded cache here</body></html>";
    let err = build_enrichment_report(html, SOURCE, NOW, None).expect_err("no marker");
    assert_eq!(err.code(), "invalid_request");
    assert!(!err.safe_message().is_empty());
}

#[test]
fn non_object_cache_is_rejected() {
    let err =
        build_enrichment_report(&page("[1, 2, 3]"), SOURCE, NOW, None).expect_err("array cache");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn missing_company_entry_is_rejected() {
    let payload = r#"{ "queries": [ { "queryKey": ["other"], "state": { "data": {} } } ] }"#;
    let err =
        build_enrichment_report(&page(payload), SOURCE, NOW, None).expect_err("no company entry");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn oversized_page_is_rejected() {
    let html = "x".repeat(4 * 1024 * 1024 + 1);
    let err = build_enrichment_report(&html, SOURCE, NOW, None).expect_err("too large");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn long_text_and_wide_sections_are_bounded() {
    let long = "A".repeat(10_000);
    let mut wide = String::new();
    for i in 0..40 {
        if i > 0 {
            wide.push(',');
        }
        wide.push_str(&format!("\"m{i}\": {i}"));
    }
    let payload = format!(
        r#"{{
          "queries": [{{
            "queryKey": ["company"],
            "state": {{ "data": {{ "data": {{
              "analysis": {{ "data": {{ "extended": {{ "data": {{
                "raw_data": {{ "data": {{ "company_info": {{
                  "name": "SYNTHETIC Co",
                  "description": "{long}"
                }} }} }},
                "analysis": {{ "value": {{ {wide} }} }},
                "scores": {{}}
              }} }} }} }}
            }} }} }}
          }}]
        }}"#
    );

    let report =
        build_enrichment_report(&page(&payload), SOURCE, NOW, None).expect("report should build");
    assert_eq!(report.company.description.chars().count(), 4096);
    let value_section = report.metrics["value"].as_object().expect("value object");
    assert_eq!(value_section.len(), 16);
}

#[test]
fn expected_isin_suffix_is_ignored_for_verification() {
    let report = build_enrichment_report(
        &page(&canonical_payload()),
        SOURCE,
        NOW,
        Some("IT0003153621.AF"),
    )
    .expect("report should build");

    assert_eq!(report.company.isin, "IT0003153621");
}

#[test]
fn expected_isin_mismatch_fails_closed() {
    let err = build_enrichment_report(
        &page(&canonical_payload()),
        SOURCE,
        NOW,
        Some("GB0000000000"),
    )
    .expect_err("wrong ISIN must fail closed");
    assert_eq!(err.code(), "invalid_request");
}

// ---- Source-URL allowlisting ----------------------------------------------

fn allowlist() -> EnrichmentHostAllowlist {
    EnrichmentHostAllowlist::from_allowed_hosts(["stocks.example"])
}

#[test]
fn accepts_allowlisted_https_stock_url() {
    assert!(validate_source_url(SOURCE, &allowlist()).is_ok());
    // A locale-prefixed path is accepted (the locale is stripped before the
    // stock-page route check).
    assert!(validate_source_url("https://stocks.example/it/stocks/foo/bar", &allowlist()).is_ok());
    assert!(validate_source_url("https://stocks.example/stock/LSE/VHYL", &allowlist()).is_ok());
    assert!(validate_source_url("https://stocks.example/it/stock/LSE/VHYL", &allowlist()).is_ok());
}

#[test]
fn rejects_http_scheme() {
    let err = validate_source_url("http://stocks.example/stocks/x", &allowlist())
        .expect_err("http must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn rejects_unlisted_host() {
    let err = validate_source_url("https://evil.example/stocks/x", &allowlist())
        .expect_err("unlisted host");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn rejects_userinfo() {
    let err = validate_source_url("https://user:pass@stocks.example/stocks/x", &allowlist())
        .expect_err("userinfo must be rejected");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn rejects_non_stock_path() {
    let err = validate_source_url("https://stocks.example/markets/x", &allowlist())
        .expect_err("non-stock path");
    assert_eq!(err.code(), "invalid_request");
}

#[test]
fn host_is_matched_case_insensitively_without_port() {
    assert!(validate_source_url("https://STOCKS.example:443/stocks/x", &allowlist()).is_ok());
}

#[test]
fn accepts_bracketed_ipv6_host() {
    // A bracketed IPv6 authority must normalize to the address (not `[`), so the
    // host pin matches with or without a port.
    let allow = EnrichmentHostAllowlist::from_allowed_hosts(["[::1]"]);
    assert!(validate_source_url("https://[::1]/stocks/x", &allow).is_ok());
    assert!(validate_source_url("https://[::1]:8443/stocks/x", &allow).is_ok());
    // A different IPv6 host is still rejected.
    assert!(validate_source_url("https://[::2]/stocks/x", &allow).is_err());
}

#[test]
fn rejects_malformed_non_numeric_port() {
    // A malformed authority must not slip through host normalization (which
    // would otherwise strip the bad port and accept the host).
    let err = validate_source_url("https://stocks.example:notaport/stocks/x", &allowlist())
        .expect_err("non-numeric port must be rejected");
    assert_eq!(err.code(), "invalid_request");
}
