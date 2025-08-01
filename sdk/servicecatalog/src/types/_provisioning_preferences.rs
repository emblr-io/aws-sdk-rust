// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The user-defined preferences that will be applied when updating a provisioned product. Not all preferences are applicable to all provisioned product type</p>
/// <p>One or more Amazon Web Services accounts that will have access to the provisioned product.</p>
/// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
/// <p>The Amazon Web Services accounts specified should be within the list of accounts in the <code>STACKSET</code> constraint. To get the list of accounts in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
/// <p>If no values are specified, the default value is all accounts from the <code>STACKSET</code> constraint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisioningPreferences {
    /// <p>One or more Amazon Web Services accounts where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified accounts should be within the list of accounts from the <code>STACKSET</code> constraint. To get the list of accounts in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all acounts from the <code>STACKSET</code> constraint.</p>
    pub stack_set_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>One or more Amazon Web Services Regions where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified Regions should be within the list of Regions from the <code>STACKSET</code> constraint. To get the list of Regions in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all Regions from the <code>STACKSET</code> constraint.</p>
    pub stack_set_regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The number of accounts, per Region, for which this operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    /// <p>The default value is <code>0</code> if no value is specified.</p>
    pub stack_set_failure_tolerance_count: ::std::option::Option<i32>,
    /// <p>The percentage of accounts, per Region, for which this stack operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    pub stack_set_failure_tolerance_percentage: ::std::option::Option<i32>,
    /// <p>The maximum number of accounts in which to perform this operation at one time. This is dependent on the value of <code>StackSetFailureToleranceCount</code>. <code>StackSetMaxConcurrentCount</code> is at most one more than the <code>StackSetFailureToleranceCount</code>.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub stack_set_max_concurrency_count: ::std::option::Option<i32>,
    /// <p>The maximum percentage of accounts in which to perform this operation at one time.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number. This is true except in cases where rounding down would result is zero. In this case, Service Catalog sets the number as <code>1</code> instead.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub stack_set_max_concurrency_percentage: ::std::option::Option<i32>,
}
impl ProvisioningPreferences {
    /// <p>One or more Amazon Web Services accounts where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified accounts should be within the list of accounts from the <code>STACKSET</code> constraint. To get the list of accounts in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all acounts from the <code>STACKSET</code> constraint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stack_set_accounts.is_none()`.
    pub fn stack_set_accounts(&self) -> &[::std::string::String] {
        self.stack_set_accounts.as_deref().unwrap_or_default()
    }
    /// <p>One or more Amazon Web Services Regions where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified Regions should be within the list of Regions from the <code>STACKSET</code> constraint. To get the list of Regions in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all Regions from the <code>STACKSET</code> constraint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.stack_set_regions.is_none()`.
    pub fn stack_set_regions(&self) -> &[::std::string::String] {
        self.stack_set_regions.as_deref().unwrap_or_default()
    }
    /// <p>The number of accounts, per Region, for which this operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    /// <p>The default value is <code>0</code> if no value is specified.</p>
    pub fn stack_set_failure_tolerance_count(&self) -> ::std::option::Option<i32> {
        self.stack_set_failure_tolerance_count
    }
    /// <p>The percentage of accounts, per Region, for which this stack operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    pub fn stack_set_failure_tolerance_percentage(&self) -> ::std::option::Option<i32> {
        self.stack_set_failure_tolerance_percentage
    }
    /// <p>The maximum number of accounts in which to perform this operation at one time. This is dependent on the value of <code>StackSetFailureToleranceCount</code>. <code>StackSetMaxConcurrentCount</code> is at most one more than the <code>StackSetFailureToleranceCount</code>.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn stack_set_max_concurrency_count(&self) -> ::std::option::Option<i32> {
        self.stack_set_max_concurrency_count
    }
    /// <p>The maximum percentage of accounts in which to perform this operation at one time.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number. This is true except in cases where rounding down would result is zero. In this case, Service Catalog sets the number as <code>1</code> instead.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn stack_set_max_concurrency_percentage(&self) -> ::std::option::Option<i32> {
        self.stack_set_max_concurrency_percentage
    }
}
impl ProvisioningPreferences {
    /// Creates a new builder-style object to manufacture [`ProvisioningPreferences`](crate::types::ProvisioningPreferences).
    pub fn builder() -> crate::types::builders::ProvisioningPreferencesBuilder {
        crate::types::builders::ProvisioningPreferencesBuilder::default()
    }
}

/// A builder for [`ProvisioningPreferences`](crate::types::ProvisioningPreferences).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisioningPreferencesBuilder {
    pub(crate) stack_set_accounts: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) stack_set_regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) stack_set_failure_tolerance_count: ::std::option::Option<i32>,
    pub(crate) stack_set_failure_tolerance_percentage: ::std::option::Option<i32>,
    pub(crate) stack_set_max_concurrency_count: ::std::option::Option<i32>,
    pub(crate) stack_set_max_concurrency_percentage: ::std::option::Option<i32>,
}
impl ProvisioningPreferencesBuilder {
    /// Appends an item to `stack_set_accounts`.
    ///
    /// To override the contents of this collection use [`set_stack_set_accounts`](Self::set_stack_set_accounts).
    ///
    /// <p>One or more Amazon Web Services accounts where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified accounts should be within the list of accounts from the <code>STACKSET</code> constraint. To get the list of accounts in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all acounts from the <code>STACKSET</code> constraint.</p>
    pub fn stack_set_accounts(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.stack_set_accounts.unwrap_or_default();
        v.push(input.into());
        self.stack_set_accounts = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more Amazon Web Services accounts where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified accounts should be within the list of accounts from the <code>STACKSET</code> constraint. To get the list of accounts in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all acounts from the <code>STACKSET</code> constraint.</p>
    pub fn set_stack_set_accounts(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.stack_set_accounts = input;
        self
    }
    /// <p>One or more Amazon Web Services accounts where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified accounts should be within the list of accounts from the <code>STACKSET</code> constraint. To get the list of accounts in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all acounts from the <code>STACKSET</code> constraint.</p>
    pub fn get_stack_set_accounts(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.stack_set_accounts
    }
    /// Appends an item to `stack_set_regions`.
    ///
    /// To override the contents of this collection use [`set_stack_set_regions`](Self::set_stack_set_regions).
    ///
    /// <p>One or more Amazon Web Services Regions where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified Regions should be within the list of Regions from the <code>STACKSET</code> constraint. To get the list of Regions in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all Regions from the <code>STACKSET</code> constraint.</p>
    pub fn stack_set_regions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.stack_set_regions.unwrap_or_default();
        v.push(input.into());
        self.stack_set_regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more Amazon Web Services Regions where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified Regions should be within the list of Regions from the <code>STACKSET</code> constraint. To get the list of Regions in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all Regions from the <code>STACKSET</code> constraint.</p>
    pub fn set_stack_set_regions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.stack_set_regions = input;
        self
    }
    /// <p>One or more Amazon Web Services Regions where the provisioned product will be available.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>The specified Regions should be within the list of Regions from the <code>STACKSET</code> constraint. To get the list of Regions in the <code>STACKSET</code> constraint, use the <code>DescribeProvisioningParameters</code> operation.</p>
    /// <p>If no values are specified, the default value is all Regions from the <code>STACKSET</code> constraint.</p>
    pub fn get_stack_set_regions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.stack_set_regions
    }
    /// <p>The number of accounts, per Region, for which this operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    /// <p>The default value is <code>0</code> if no value is specified.</p>
    pub fn stack_set_failure_tolerance_count(mut self, input: i32) -> Self {
        self.stack_set_failure_tolerance_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of accounts, per Region, for which this operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    /// <p>The default value is <code>0</code> if no value is specified.</p>
    pub fn set_stack_set_failure_tolerance_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.stack_set_failure_tolerance_count = input;
        self
    }
    /// <p>The number of accounts, per Region, for which this operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    /// <p>The default value is <code>0</code> if no value is specified.</p>
    pub fn get_stack_set_failure_tolerance_count(&self) -> &::std::option::Option<i32> {
        &self.stack_set_failure_tolerance_count
    }
    /// <p>The percentage of accounts, per Region, for which this stack operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    pub fn stack_set_failure_tolerance_percentage(mut self, input: i32) -> Self {
        self.stack_set_failure_tolerance_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The percentage of accounts, per Region, for which this stack operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    pub fn set_stack_set_failure_tolerance_percentage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.stack_set_failure_tolerance_percentage = input;
        self
    }
    /// <p>The percentage of accounts, per Region, for which this stack operation can fail before Service Catalog stops the operation in that Region. If the operation is stopped in a Region, Service Catalog doesn't attempt the operation in any subsequent Regions.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetFailureToleranceCount</code> or <code>StackSetFailureTolerancePercentage</code>, but not both.</p>
    pub fn get_stack_set_failure_tolerance_percentage(&self) -> &::std::option::Option<i32> {
        &self.stack_set_failure_tolerance_percentage
    }
    /// <p>The maximum number of accounts in which to perform this operation at one time. This is dependent on the value of <code>StackSetFailureToleranceCount</code>. <code>StackSetMaxConcurrentCount</code> is at most one more than the <code>StackSetFailureToleranceCount</code>.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn stack_set_max_concurrency_count(mut self, input: i32) -> Self {
        self.stack_set_max_concurrency_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of accounts in which to perform this operation at one time. This is dependent on the value of <code>StackSetFailureToleranceCount</code>. <code>StackSetMaxConcurrentCount</code> is at most one more than the <code>StackSetFailureToleranceCount</code>.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn set_stack_set_max_concurrency_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.stack_set_max_concurrency_count = input;
        self
    }
    /// <p>The maximum number of accounts in which to perform this operation at one time. This is dependent on the value of <code>StackSetFailureToleranceCount</code>. <code>StackSetMaxConcurrentCount</code> is at most one more than the <code>StackSetFailureToleranceCount</code>.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn get_stack_set_max_concurrency_count(&self) -> &::std::option::Option<i32> {
        &self.stack_set_max_concurrency_count
    }
    /// <p>The maximum percentage of accounts in which to perform this operation at one time.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number. This is true except in cases where rounding down would result is zero. In this case, Service Catalog sets the number as <code>1</code> instead.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn stack_set_max_concurrency_percentage(mut self, input: i32) -> Self {
        self.stack_set_max_concurrency_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum percentage of accounts in which to perform this operation at one time.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number. This is true except in cases where rounding down would result is zero. In this case, Service Catalog sets the number as <code>1</code> instead.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn set_stack_set_max_concurrency_percentage(mut self, input: ::std::option::Option<i32>) -> Self {
        self.stack_set_max_concurrency_percentage = input;
        self
    }
    /// <p>The maximum percentage of accounts in which to perform this operation at one time.</p>
    /// <p>When calculating the number of accounts based on the specified percentage, Service Catalog rounds down to the next whole number. This is true except in cases where rounding down would result is zero. In this case, Service Catalog sets the number as <code>1</code> instead.</p>
    /// <p>Note that this setting lets you specify the maximum for operations. For large deployments, under certain circumstances the actual number of accounts acted upon concurrently may be lower due to service throttling.</p>
    /// <p>Applicable only to a <code>CFN_STACKSET</code> provisioned product type.</p>
    /// <p>Conditional: You must specify either <code>StackSetMaxConcurrentCount</code> or <code>StackSetMaxConcurrentPercentage</code>, but not both.</p>
    pub fn get_stack_set_max_concurrency_percentage(&self) -> &::std::option::Option<i32> {
        &self.stack_set_max_concurrency_percentage
    }
    /// Consumes the builder and constructs a [`ProvisioningPreferences`](crate::types::ProvisioningPreferences).
    pub fn build(self) -> crate::types::ProvisioningPreferences {
        crate::types::ProvisioningPreferences {
            stack_set_accounts: self.stack_set_accounts,
            stack_set_regions: self.stack_set_regions,
            stack_set_failure_tolerance_count: self.stack_set_failure_tolerance_count,
            stack_set_failure_tolerance_percentage: self.stack_set_failure_tolerance_percentage,
            stack_set_max_concurrency_count: self.stack_set_max_concurrency_count,
            stack_set_max_concurrency_percentage: self.stack_set_max_concurrency_percentage,
        }
    }
}
