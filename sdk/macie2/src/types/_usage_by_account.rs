// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides data for a specific usage metric and the corresponding quota for an Amazon Macie account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UsageByAccount {
    /// <p>The type of currency that the value for the metric (estimatedCost) is reported in.</p>
    pub currency: ::std::option::Option<crate::types::Currency>,
    /// <p>The estimated value for the metric.</p>
    pub estimated_cost: ::std::option::Option<::std::string::String>,
    /// <p>The current value for the quota that corresponds to the metric specified by the type field.</p>
    pub service_limit: ::std::option::Option<crate::types::ServiceLimit>,
    /// <p>The name of the metric. Possible values are: AUTOMATED_OBJECT_MONITORING, to monitor S3 objects for automated sensitive data discovery; AUTOMATED_SENSITIVE_DATA_DISCOVERY, to analyze S3 objects for automated sensitive data discovery; DATA_INVENTORY_EVALUATION, to monitor S3 buckets; and, SENSITIVE_DATA_DISCOVERY, to run classification jobs.</p>
    pub r#type: ::std::option::Option<crate::types::UsageType>,
}
impl UsageByAccount {
    /// <p>The type of currency that the value for the metric (estimatedCost) is reported in.</p>
    pub fn currency(&self) -> ::std::option::Option<&crate::types::Currency> {
        self.currency.as_ref()
    }
    /// <p>The estimated value for the metric.</p>
    pub fn estimated_cost(&self) -> ::std::option::Option<&str> {
        self.estimated_cost.as_deref()
    }
    /// <p>The current value for the quota that corresponds to the metric specified by the type field.</p>
    pub fn service_limit(&self) -> ::std::option::Option<&crate::types::ServiceLimit> {
        self.service_limit.as_ref()
    }
    /// <p>The name of the metric. Possible values are: AUTOMATED_OBJECT_MONITORING, to monitor S3 objects for automated sensitive data discovery; AUTOMATED_SENSITIVE_DATA_DISCOVERY, to analyze S3 objects for automated sensitive data discovery; DATA_INVENTORY_EVALUATION, to monitor S3 buckets; and, SENSITIVE_DATA_DISCOVERY, to run classification jobs.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::UsageType> {
        self.r#type.as_ref()
    }
}
impl UsageByAccount {
    /// Creates a new builder-style object to manufacture [`UsageByAccount`](crate::types::UsageByAccount).
    pub fn builder() -> crate::types::builders::UsageByAccountBuilder {
        crate::types::builders::UsageByAccountBuilder::default()
    }
}

/// A builder for [`UsageByAccount`](crate::types::UsageByAccount).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UsageByAccountBuilder {
    pub(crate) currency: ::std::option::Option<crate::types::Currency>,
    pub(crate) estimated_cost: ::std::option::Option<::std::string::String>,
    pub(crate) service_limit: ::std::option::Option<crate::types::ServiceLimit>,
    pub(crate) r#type: ::std::option::Option<crate::types::UsageType>,
}
impl UsageByAccountBuilder {
    /// <p>The type of currency that the value for the metric (estimatedCost) is reported in.</p>
    pub fn currency(mut self, input: crate::types::Currency) -> Self {
        self.currency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of currency that the value for the metric (estimatedCost) is reported in.</p>
    pub fn set_currency(mut self, input: ::std::option::Option<crate::types::Currency>) -> Self {
        self.currency = input;
        self
    }
    /// <p>The type of currency that the value for the metric (estimatedCost) is reported in.</p>
    pub fn get_currency(&self) -> &::std::option::Option<crate::types::Currency> {
        &self.currency
    }
    /// <p>The estimated value for the metric.</p>
    pub fn estimated_cost(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.estimated_cost = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The estimated value for the metric.</p>
    pub fn set_estimated_cost(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.estimated_cost = input;
        self
    }
    /// <p>The estimated value for the metric.</p>
    pub fn get_estimated_cost(&self) -> &::std::option::Option<::std::string::String> {
        &self.estimated_cost
    }
    /// <p>The current value for the quota that corresponds to the metric specified by the type field.</p>
    pub fn service_limit(mut self, input: crate::types::ServiceLimit) -> Self {
        self.service_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current value for the quota that corresponds to the metric specified by the type field.</p>
    pub fn set_service_limit(mut self, input: ::std::option::Option<crate::types::ServiceLimit>) -> Self {
        self.service_limit = input;
        self
    }
    /// <p>The current value for the quota that corresponds to the metric specified by the type field.</p>
    pub fn get_service_limit(&self) -> &::std::option::Option<crate::types::ServiceLimit> {
        &self.service_limit
    }
    /// <p>The name of the metric. Possible values are: AUTOMATED_OBJECT_MONITORING, to monitor S3 objects for automated sensitive data discovery; AUTOMATED_SENSITIVE_DATA_DISCOVERY, to analyze S3 objects for automated sensitive data discovery; DATA_INVENTORY_EVALUATION, to monitor S3 buckets; and, SENSITIVE_DATA_DISCOVERY, to run classification jobs.</p>
    pub fn r#type(mut self, input: crate::types::UsageType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the metric. Possible values are: AUTOMATED_OBJECT_MONITORING, to monitor S3 objects for automated sensitive data discovery; AUTOMATED_SENSITIVE_DATA_DISCOVERY, to analyze S3 objects for automated sensitive data discovery; DATA_INVENTORY_EVALUATION, to monitor S3 buckets; and, SENSITIVE_DATA_DISCOVERY, to run classification jobs.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::UsageType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The name of the metric. Possible values are: AUTOMATED_OBJECT_MONITORING, to monitor S3 objects for automated sensitive data discovery; AUTOMATED_SENSITIVE_DATA_DISCOVERY, to analyze S3 objects for automated sensitive data discovery; DATA_INVENTORY_EVALUATION, to monitor S3 buckets; and, SENSITIVE_DATA_DISCOVERY, to run classification jobs.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::UsageType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`UsageByAccount`](crate::types::UsageByAccount).
    pub fn build(self) -> crate::types::UsageByAccount {
        crate::types::UsageByAccount {
            currency: self.currency,
            estimated_cost: self.estimated_cost,
            service_limit: self.service_limit,
            r#type: self.r#type,
        }
    }
}
