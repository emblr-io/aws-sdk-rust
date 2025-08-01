// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents an entry in a batch operation to create bill scenario usage modifications.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchCreateBillScenarioUsageModificationEntry {
    /// <p>The Amazon Web Services service code for this usage modification. This identifies the specific Amazon Web Services service to the customer as a unique short abbreviation. For example, <code>AmazonEC2</code> and <code>AWSKMS</code>.</p>
    pub service_code: ::std::string::String,
    /// <p>Describes the usage details of the usage line item.</p>
    pub usage_type: ::std::string::String,
    /// <p>The specific operation associated with this usage modification. Describes the specific Amazon Web Services operation that this usage line models. For example, <code>RunInstances</code> indicates the operation of an Amazon EC2 instance.</p>
    pub operation: ::std::string::String,
    /// <p>The Availability Zone that this usage line uses.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any usage entry as any error is returned with this key.</p>
    pub key: ::std::string::String,
    /// <p>An optional group identifier for the usage modification.</p>
    pub group: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID to which this usage will be applied to.</p>
    pub usage_account_id: ::std::string::String,
    /// <p>The amount of usage you want to create for the service use you are modeling.</p>
    pub amounts: ::std::option::Option<::std::vec::Vec<crate::types::UsageAmount>>,
    /// <p>Historical usage data associated with this modification, if available.</p>
    pub historical_usage: ::std::option::Option<crate::types::HistoricalUsageEntity>,
}
impl BatchCreateBillScenarioUsageModificationEntry {
    /// <p>The Amazon Web Services service code for this usage modification. This identifies the specific Amazon Web Services service to the customer as a unique short abbreviation. For example, <code>AmazonEC2</code> and <code>AWSKMS</code>.</p>
    pub fn service_code(&self) -> &str {
        use std::ops::Deref;
        self.service_code.deref()
    }
    /// <p>Describes the usage details of the usage line item.</p>
    pub fn usage_type(&self) -> &str {
        use std::ops::Deref;
        self.usage_type.deref()
    }
    /// <p>The specific operation associated with this usage modification. Describes the specific Amazon Web Services operation that this usage line models. For example, <code>RunInstances</code> indicates the operation of an Amazon EC2 instance.</p>
    pub fn operation(&self) -> &str {
        use std::ops::Deref;
        self.operation.deref()
    }
    /// <p>The Availability Zone that this usage line uses.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any usage entry as any error is returned with this key.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>An optional group identifier for the usage modification.</p>
    pub fn group(&self) -> ::std::option::Option<&str> {
        self.group.as_deref()
    }
    /// <p>The Amazon Web Services account ID to which this usage will be applied to.</p>
    pub fn usage_account_id(&self) -> &str {
        use std::ops::Deref;
        self.usage_account_id.deref()
    }
    /// <p>The amount of usage you want to create for the service use you are modeling.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.amounts.is_none()`.
    pub fn amounts(&self) -> &[crate::types::UsageAmount] {
        self.amounts.as_deref().unwrap_or_default()
    }
    /// <p>Historical usage data associated with this modification, if available.</p>
    pub fn historical_usage(&self) -> ::std::option::Option<&crate::types::HistoricalUsageEntity> {
        self.historical_usage.as_ref()
    }
}
impl BatchCreateBillScenarioUsageModificationEntry {
    /// Creates a new builder-style object to manufacture [`BatchCreateBillScenarioUsageModificationEntry`](crate::types::BatchCreateBillScenarioUsageModificationEntry).
    pub fn builder() -> crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder {
        crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder::default()
    }
}

/// A builder for [`BatchCreateBillScenarioUsageModificationEntry`](crate::types::BatchCreateBillScenarioUsageModificationEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchCreateBillScenarioUsageModificationEntryBuilder {
    pub(crate) service_code: ::std::option::Option<::std::string::String>,
    pub(crate) usage_type: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) group: ::std::option::Option<::std::string::String>,
    pub(crate) usage_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) amounts: ::std::option::Option<::std::vec::Vec<crate::types::UsageAmount>>,
    pub(crate) historical_usage: ::std::option::Option<crate::types::HistoricalUsageEntity>,
}
impl BatchCreateBillScenarioUsageModificationEntryBuilder {
    /// <p>The Amazon Web Services service code for this usage modification. This identifies the specific Amazon Web Services service to the customer as a unique short abbreviation. For example, <code>AmazonEC2</code> and <code>AWSKMS</code>.</p>
    /// This field is required.
    pub fn service_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services service code for this usage modification. This identifies the specific Amazon Web Services service to the customer as a unique short abbreviation. For example, <code>AmazonEC2</code> and <code>AWSKMS</code>.</p>
    pub fn set_service_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_code = input;
        self
    }
    /// <p>The Amazon Web Services service code for this usage modification. This identifies the specific Amazon Web Services service to the customer as a unique short abbreviation. For example, <code>AmazonEC2</code> and <code>AWSKMS</code>.</p>
    pub fn get_service_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_code
    }
    /// <p>Describes the usage details of the usage line item.</p>
    /// This field is required.
    pub fn usage_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Describes the usage details of the usage line item.</p>
    pub fn set_usage_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_type = input;
        self
    }
    /// <p>Describes the usage details of the usage line item.</p>
    pub fn get_usage_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_type
    }
    /// <p>The specific operation associated with this usage modification. Describes the specific Amazon Web Services operation that this usage line models. For example, <code>RunInstances</code> indicates the operation of an Amazon EC2 instance.</p>
    /// This field is required.
    pub fn operation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The specific operation associated with this usage modification. Describes the specific Amazon Web Services operation that this usage line models. For example, <code>RunInstances</code> indicates the operation of an Amazon EC2 instance.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation = input;
        self
    }
    /// <p>The specific operation associated with this usage modification. Describes the specific Amazon Web Services operation that this usage line models. For example, <code>RunInstances</code> indicates the operation of an Amazon EC2 instance.</p>
    pub fn get_operation(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation
    }
    /// <p>The Availability Zone that this usage line uses.</p>
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Availability Zone that this usage line uses.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>The Availability Zone that this usage line uses.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any usage entry as any error is returned with this key.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any usage entry as any error is returned with this key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>A unique identifier for this entry in the batch operation. This can be any valid string. This key is useful to identify errors associated with any usage entry as any error is returned with this key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>An optional group identifier for the usage modification.</p>
    pub fn group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional group identifier for the usage modification.</p>
    pub fn set_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group = input;
        self
    }
    /// <p>An optional group identifier for the usage modification.</p>
    pub fn get_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.group
    }
    /// <p>The Amazon Web Services account ID to which this usage will be applied to.</p>
    /// This field is required.
    pub fn usage_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.usage_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID to which this usage will be applied to.</p>
    pub fn set_usage_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.usage_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID to which this usage will be applied to.</p>
    pub fn get_usage_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.usage_account_id
    }
    /// Appends an item to `amounts`.
    ///
    /// To override the contents of this collection use [`set_amounts`](Self::set_amounts).
    ///
    /// <p>The amount of usage you want to create for the service use you are modeling.</p>
    pub fn amounts(mut self, input: crate::types::UsageAmount) -> Self {
        let mut v = self.amounts.unwrap_or_default();
        v.push(input);
        self.amounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The amount of usage you want to create for the service use you are modeling.</p>
    pub fn set_amounts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UsageAmount>>) -> Self {
        self.amounts = input;
        self
    }
    /// <p>The amount of usage you want to create for the service use you are modeling.</p>
    pub fn get_amounts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UsageAmount>> {
        &self.amounts
    }
    /// <p>Historical usage data associated with this modification, if available.</p>
    pub fn historical_usage(mut self, input: crate::types::HistoricalUsageEntity) -> Self {
        self.historical_usage = ::std::option::Option::Some(input);
        self
    }
    /// <p>Historical usage data associated with this modification, if available.</p>
    pub fn set_historical_usage(mut self, input: ::std::option::Option<crate::types::HistoricalUsageEntity>) -> Self {
        self.historical_usage = input;
        self
    }
    /// <p>Historical usage data associated with this modification, if available.</p>
    pub fn get_historical_usage(&self) -> &::std::option::Option<crate::types::HistoricalUsageEntity> {
        &self.historical_usage
    }
    /// Consumes the builder and constructs a [`BatchCreateBillScenarioUsageModificationEntry`](crate::types::BatchCreateBillScenarioUsageModificationEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`service_code`](crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder::service_code)
    /// - [`usage_type`](crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder::usage_type)
    /// - [`operation`](crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder::operation)
    /// - [`key`](crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder::key)
    /// - [`usage_account_id`](crate::types::builders::BatchCreateBillScenarioUsageModificationEntryBuilder::usage_account_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::BatchCreateBillScenarioUsageModificationEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::BatchCreateBillScenarioUsageModificationEntry {
            service_code: self.service_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_code",
                    "service_code was not specified but it is required when building BatchCreateBillScenarioUsageModificationEntry",
                )
            })?,
            usage_type: self.usage_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "usage_type",
                    "usage_type was not specified but it is required when building BatchCreateBillScenarioUsageModificationEntry",
                )
            })?,
            operation: self.operation.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operation",
                    "operation was not specified but it is required when building BatchCreateBillScenarioUsageModificationEntry",
                )
            })?,
            availability_zone: self.availability_zone,
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building BatchCreateBillScenarioUsageModificationEntry",
                )
            })?,
            group: self.group,
            usage_account_id: self.usage_account_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "usage_account_id",
                    "usage_account_id was not specified but it is required when building BatchCreateBillScenarioUsageModificationEntry",
                )
            })?,
            amounts: self.amounts,
            historical_usage: self.historical_usage,
        })
    }
}
