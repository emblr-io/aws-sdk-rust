// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Controls on the query specifications that can be run on configured table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum AnalysisRulePolicyV1 {
    /// <p>Analysis rule type that enables only aggregation queries on a configured table.</p>
    Aggregation(crate::types::AnalysisRuleAggregation),
    /// <p>Analysis rule type that enables custom SQL queries on a configured table.</p>
    Custom(crate::types::AnalysisRuleCustom),
    /// <p>The ID mapping table.</p>
    IdMappingTable(crate::types::AnalysisRuleIdMappingTable),
    /// <p>Analysis rule type that enables only list queries on a configured table.</p>
    List(crate::types::AnalysisRuleList),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl AnalysisRulePolicyV1 {
    /// Tries to convert the enum instance into [`Aggregation`](crate::types::AnalysisRulePolicyV1::Aggregation), extracting the inner [`AnalysisRuleAggregation`](crate::types::AnalysisRuleAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_aggregation(&self) -> ::std::result::Result<&crate::types::AnalysisRuleAggregation, &Self> {
        if let AnalysisRulePolicyV1::Aggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Aggregation`](crate::types::AnalysisRulePolicyV1::Aggregation).
    pub fn is_aggregation(&self) -> bool {
        self.as_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`Custom`](crate::types::AnalysisRulePolicyV1::Custom), extracting the inner [`AnalysisRuleCustom`](crate::types::AnalysisRuleCustom).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_custom(&self) -> ::std::result::Result<&crate::types::AnalysisRuleCustom, &Self> {
        if let AnalysisRulePolicyV1::Custom(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Custom`](crate::types::AnalysisRulePolicyV1::Custom).
    pub fn is_custom(&self) -> bool {
        self.as_custom().is_ok()
    }
    /// Tries to convert the enum instance into [`IdMappingTable`](crate::types::AnalysisRulePolicyV1::IdMappingTable), extracting the inner [`AnalysisRuleIdMappingTable`](crate::types::AnalysisRuleIdMappingTable).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_id_mapping_table(&self) -> ::std::result::Result<&crate::types::AnalysisRuleIdMappingTable, &Self> {
        if let AnalysisRulePolicyV1::IdMappingTable(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`IdMappingTable`](crate::types::AnalysisRulePolicyV1::IdMappingTable).
    pub fn is_id_mapping_table(&self) -> bool {
        self.as_id_mapping_table().is_ok()
    }
    /// Tries to convert the enum instance into [`List`](crate::types::AnalysisRulePolicyV1::List), extracting the inner [`AnalysisRuleList`](crate::types::AnalysisRuleList).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_list(&self) -> ::std::result::Result<&crate::types::AnalysisRuleList, &Self> {
        if let AnalysisRulePolicyV1::List(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`List`](crate::types::AnalysisRulePolicyV1::List).
    pub fn is_list(&self) -> bool {
        self.as_list().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
