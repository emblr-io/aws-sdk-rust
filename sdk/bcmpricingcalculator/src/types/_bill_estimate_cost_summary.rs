// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides a summary of cost-related information for a bill estimate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BillEstimateCostSummary {
    /// <p>The total difference in cost between the estimated and historical costs.</p>
    pub total_cost_difference: ::std::option::Option<crate::types::CostDifference>,
    /// <p>A breakdown of cost differences by Amazon Web Services service.</p>
    pub service_cost_differences: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CostDifference>>,
}
impl BillEstimateCostSummary {
    /// <p>The total difference in cost between the estimated and historical costs.</p>
    pub fn total_cost_difference(&self) -> ::std::option::Option<&crate::types::CostDifference> {
        self.total_cost_difference.as_ref()
    }
    /// <p>A breakdown of cost differences by Amazon Web Services service.</p>
    pub fn service_cost_differences(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::CostDifference>> {
        self.service_cost_differences.as_ref()
    }
}
impl BillEstimateCostSummary {
    /// Creates a new builder-style object to manufacture [`BillEstimateCostSummary`](crate::types::BillEstimateCostSummary).
    pub fn builder() -> crate::types::builders::BillEstimateCostSummaryBuilder {
        crate::types::builders::BillEstimateCostSummaryBuilder::default()
    }
}

/// A builder for [`BillEstimateCostSummary`](crate::types::BillEstimateCostSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BillEstimateCostSummaryBuilder {
    pub(crate) total_cost_difference: ::std::option::Option<crate::types::CostDifference>,
    pub(crate) service_cost_differences: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CostDifference>>,
}
impl BillEstimateCostSummaryBuilder {
    /// <p>The total difference in cost between the estimated and historical costs.</p>
    pub fn total_cost_difference(mut self, input: crate::types::CostDifference) -> Self {
        self.total_cost_difference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total difference in cost between the estimated and historical costs.</p>
    pub fn set_total_cost_difference(mut self, input: ::std::option::Option<crate::types::CostDifference>) -> Self {
        self.total_cost_difference = input;
        self
    }
    /// <p>The total difference in cost between the estimated and historical costs.</p>
    pub fn get_total_cost_difference(&self) -> &::std::option::Option<crate::types::CostDifference> {
        &self.total_cost_difference
    }
    /// Adds a key-value pair to `service_cost_differences`.
    ///
    /// To override the contents of this collection use [`set_service_cost_differences`](Self::set_service_cost_differences).
    ///
    /// <p>A breakdown of cost differences by Amazon Web Services service.</p>
    pub fn service_cost_differences(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::CostDifference) -> Self {
        let mut hash_map = self.service_cost_differences.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.service_cost_differences = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A breakdown of cost differences by Amazon Web Services service.</p>
    pub fn set_service_cost_differences(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CostDifference>>,
    ) -> Self {
        self.service_cost_differences = input;
        self
    }
    /// <p>A breakdown of cost differences by Amazon Web Services service.</p>
    pub fn get_service_cost_differences(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::CostDifference>> {
        &self.service_cost_differences
    }
    /// Consumes the builder and constructs a [`BillEstimateCostSummary`](crate::types::BillEstimateCostSummary).
    pub fn build(self) -> crate::types::BillEstimateCostSummary {
        crate::types::BillEstimateCostSummary {
            total_cost_difference: self.total_cost_difference,
            service_cost_differences: self.service_cost_differences,
        }
    }
}
