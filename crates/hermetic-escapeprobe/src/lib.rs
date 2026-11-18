//! Escape probe (TR-SEC-6). Guest side: `probes::run_all` tries every
//! documented way out of AgentVM. Host side: `report::aggregate` turns the
//! guest's JSON lines into one fail-closed verdict.
pub mod classify;
pub mod config;
pub mod dns;
pub mod gateway;
pub mod http;
pub mod install;
pub mod probes;
pub mod report;
pub mod sys;
