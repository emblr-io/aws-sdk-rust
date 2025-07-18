// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCostComparisonDriversInput {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies a specific billing view. The ARN is used to specify which particular billing view you want to interact with or retrieve information from when making API calls related to Amazon Web Services Billing and Cost Management features. The BillingViewArn can be retrieved by calling the ListBillingViews API.</p>
    pub billing_view_arn: ::std::option::Option<::std::string::String>,
    /// <p>The reference time period for comparison. This time period serves as the baseline against which other cost and usage data will be compared. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub baseline_time_period: ::std::option::Option<crate::types::DateInterval>,
    /// <p>The comparison time period for analysis. This time period's cost and usage data will be compared against the baseline time period. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub comparison_time_period: ::std::option::Option<crate::types::DateInterval>,
    /// <p>The cost and usage metric to compare. Valid values are <code>AmortizedCost</code>, <code>BlendedCost</code>, <code>NetAmortizedCost</code>, <code>NetUnblendedCost</code>, <code>NormalizedUsageAmount</code>, <code>UnblendedCost</code>, and <code>UsageQuantity</code>.</p>
    pub metric_for_comparison: ::std::option::Option<::std::string::String>,
    /// <p>Use <code>Expression</code> to filter in various Cost Explorer APIs.</p>
    /// <p>Not all <code>Expression</code> types are supported in each API. Refer to the documentation for each specific API to see what is supported.</p>
    /// <p>There are two patterns:</p>
    /// <ul>
    /// <li>
    /// <p>Simple dimension values.</p>
    /// <ul>
    /// <li>
    /// <p>There are three types of simple dimension values: <code>CostCategories</code>, <code>Tags</code>, and <code>Dimensions</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Specify the <code>CostCategories</code> field to define a filter that acts on Cost Categories.</p></li>
    /// <li>
    /// <p>Specify the <code>Tags</code> field to define a filter that acts on Cost Allocation Tags.</p></li>
    /// <li>
    /// <p>Specify the <code>Dimensions</code> field to define a filter that acts on the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_DimensionValues.html"> <code>DimensionValues</code> </a>.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For each filter type, you can set the dimension name and values for the filters that you plan to use.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for <code>REGION==us-east-1 OR REGION==us-west-1</code>. For <code>GetRightsizingRecommendation</code>, the Region is a full name (for example, <code>REGION==US East (N. Virginia)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] } }</code></p></li>
    /// <li>
    /// <p>As shown in the previous example, lists of dimension values are combined with <code>OR</code> when applying the filter.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>You can also set different match options to further control how the filter behaves. Not all APIs support match options. Refer to the documentation for each specific API to see what is supported.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for linked account names that start with "a".</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "LINKED_ACCOUNT_NAME", "MatchOptions": \[ "STARTS_WITH" \], "Values": \[ "a" \] } }</code></p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p>Compound <code>Expression</code> types with logical operations.</p>
    /// <ul>
    /// <li>
    /// <p>You can use multiple <code>Expression</code> types and the logical operators <code>AND/OR/NOT</code> to create a list of one or more <code>Expression</code> objects. By doing this, you can filter by more advanced options.</p></li>
    /// <li>
    /// <p>For example, you can filter by <code>((REGION == us-east-1 OR REGION == us-west-1) OR (TAG.Type == Type1)) AND (USAGE_TYPE != DataTransfer)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "And": \[ {"Or": \[ {"Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] }}, {"Tags": { "Key": "TagName", "Values": \["Value1"\] } } \]}, {"Not": {"Dimensions": { "Key": "USAGE_TYPE", "Values": \["DataTransfer"\] }}} \] }</code></p></li>
    /// </ul><note>
    /// <p>Because each <code>Expression</code> can have only one operator, the service returns an error if more than one is specified. The following example shows an <code>Expression</code> object that creates an error: <code>{ "And": \[ ... \], "Dimensions": { "Key": "USAGE_TYPE", "Values": \[ "DataTransfer" \] } }</code></p>
    /// <p>The following is an example of the corresponding error message: <code>"Expression has more than one roots. Only one root operator is allowed for each expression: And, Or, Not, Dimensions, Tags, CostCategories"</code></p>
    /// </note></li>
    /// </ul><note>
    /// <p>For the <code>GetRightsizingRecommendation</code> action, a combination of OR and NOT isn't supported. OR isn't supported between different dimensions, or dimensions and tags. NOT operators aren't supported. Dimensions are also limited to <code>LINKED_ACCOUNT</code>, <code>REGION</code>, or <code>RIGHTSIZING_TYPE</code>.</p>
    /// <p>For the <code>GetReservationPurchaseRecommendation</code> action, only NOT is supported. AND and OR aren't supported. Dimensions are limited to <code>LINKED_ACCOUNT</code>.</p>
    /// </note>
    pub filter: ::std::option::Option<crate::types::Expression>,
    /// <p>You can group results using the attributes <code>DIMENSION</code>, <code>TAG</code>, and <code>COST_CATEGORY</code>. Note that <code>SERVICE</code> and <code>USAGE_TYPE</code> dimensions are automatically included in the cost comparison drivers analysis.</p>
    pub group_by: ::std::option::Option<::std::vec::Vec<crate::types::GroupDefinition>>,
    /// <p>The maximum number of results that are returned for the request.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token to retrieve the next set of paginated results.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
}
impl GetCostComparisonDriversInput {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies a specific billing view. The ARN is used to specify which particular billing view you want to interact with or retrieve information from when making API calls related to Amazon Web Services Billing and Cost Management features. The BillingViewArn can be retrieved by calling the ListBillingViews API.</p>
    pub fn billing_view_arn(&self) -> ::std::option::Option<&str> {
        self.billing_view_arn.as_deref()
    }
    /// <p>The reference time period for comparison. This time period serves as the baseline against which other cost and usage data will be compared. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub fn baseline_time_period(&self) -> ::std::option::Option<&crate::types::DateInterval> {
        self.baseline_time_period.as_ref()
    }
    /// <p>The comparison time period for analysis. This time period's cost and usage data will be compared against the baseline time period. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub fn comparison_time_period(&self) -> ::std::option::Option<&crate::types::DateInterval> {
        self.comparison_time_period.as_ref()
    }
    /// <p>The cost and usage metric to compare. Valid values are <code>AmortizedCost</code>, <code>BlendedCost</code>, <code>NetAmortizedCost</code>, <code>NetUnblendedCost</code>, <code>NormalizedUsageAmount</code>, <code>UnblendedCost</code>, and <code>UsageQuantity</code>.</p>
    pub fn metric_for_comparison(&self) -> ::std::option::Option<&str> {
        self.metric_for_comparison.as_deref()
    }
    /// <p>Use <code>Expression</code> to filter in various Cost Explorer APIs.</p>
    /// <p>Not all <code>Expression</code> types are supported in each API. Refer to the documentation for each specific API to see what is supported.</p>
    /// <p>There are two patterns:</p>
    /// <ul>
    /// <li>
    /// <p>Simple dimension values.</p>
    /// <ul>
    /// <li>
    /// <p>There are three types of simple dimension values: <code>CostCategories</code>, <code>Tags</code>, and <code>Dimensions</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Specify the <code>CostCategories</code> field to define a filter that acts on Cost Categories.</p></li>
    /// <li>
    /// <p>Specify the <code>Tags</code> field to define a filter that acts on Cost Allocation Tags.</p></li>
    /// <li>
    /// <p>Specify the <code>Dimensions</code> field to define a filter that acts on the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_DimensionValues.html"> <code>DimensionValues</code> </a>.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For each filter type, you can set the dimension name and values for the filters that you plan to use.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for <code>REGION==us-east-1 OR REGION==us-west-1</code>. For <code>GetRightsizingRecommendation</code>, the Region is a full name (for example, <code>REGION==US East (N. Virginia)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] } }</code></p></li>
    /// <li>
    /// <p>As shown in the previous example, lists of dimension values are combined with <code>OR</code> when applying the filter.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>You can also set different match options to further control how the filter behaves. Not all APIs support match options. Refer to the documentation for each specific API to see what is supported.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for linked account names that start with "a".</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "LINKED_ACCOUNT_NAME", "MatchOptions": \[ "STARTS_WITH" \], "Values": \[ "a" \] } }</code></p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p>Compound <code>Expression</code> types with logical operations.</p>
    /// <ul>
    /// <li>
    /// <p>You can use multiple <code>Expression</code> types and the logical operators <code>AND/OR/NOT</code> to create a list of one or more <code>Expression</code> objects. By doing this, you can filter by more advanced options.</p></li>
    /// <li>
    /// <p>For example, you can filter by <code>((REGION == us-east-1 OR REGION == us-west-1) OR (TAG.Type == Type1)) AND (USAGE_TYPE != DataTransfer)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "And": \[ {"Or": \[ {"Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] }}, {"Tags": { "Key": "TagName", "Values": \["Value1"\] } } \]}, {"Not": {"Dimensions": { "Key": "USAGE_TYPE", "Values": \["DataTransfer"\] }}} \] }</code></p></li>
    /// </ul><note>
    /// <p>Because each <code>Expression</code> can have only one operator, the service returns an error if more than one is specified. The following example shows an <code>Expression</code> object that creates an error: <code>{ "And": \[ ... \], "Dimensions": { "Key": "USAGE_TYPE", "Values": \[ "DataTransfer" \] } }</code></p>
    /// <p>The following is an example of the corresponding error message: <code>"Expression has more than one roots. Only one root operator is allowed for each expression: And, Or, Not, Dimensions, Tags, CostCategories"</code></p>
    /// </note></li>
    /// </ul><note>
    /// <p>For the <code>GetRightsizingRecommendation</code> action, a combination of OR and NOT isn't supported. OR isn't supported between different dimensions, or dimensions and tags. NOT operators aren't supported. Dimensions are also limited to <code>LINKED_ACCOUNT</code>, <code>REGION</code>, or <code>RIGHTSIZING_TYPE</code>.</p>
    /// <p>For the <code>GetReservationPurchaseRecommendation</code> action, only NOT is supported. AND and OR aren't supported. Dimensions are limited to <code>LINKED_ACCOUNT</code>.</p>
    /// </note>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::Expression> {
        self.filter.as_ref()
    }
    /// <p>You can group results using the attributes <code>DIMENSION</code>, <code>TAG</code>, and <code>COST_CATEGORY</code>. Note that <code>SERVICE</code> and <code>USAGE_TYPE</code> dimensions are automatically included in the cost comparison drivers analysis.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.group_by.is_none()`.
    pub fn group_by(&self) -> &[crate::types::GroupDefinition] {
        self.group_by.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of results that are returned for the request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token to retrieve the next set of paginated results.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl GetCostComparisonDriversInput {
    /// Creates a new builder-style object to manufacture [`GetCostComparisonDriversInput`](crate::operation::get_cost_comparison_drivers::GetCostComparisonDriversInput).
    pub fn builder() -> crate::operation::get_cost_comparison_drivers::builders::GetCostComparisonDriversInputBuilder {
        crate::operation::get_cost_comparison_drivers::builders::GetCostComparisonDriversInputBuilder::default()
    }
}

/// A builder for [`GetCostComparisonDriversInput`](crate::operation::get_cost_comparison_drivers::GetCostComparisonDriversInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCostComparisonDriversInputBuilder {
    pub(crate) billing_view_arn: ::std::option::Option<::std::string::String>,
    pub(crate) baseline_time_period: ::std::option::Option<crate::types::DateInterval>,
    pub(crate) comparison_time_period: ::std::option::Option<crate::types::DateInterval>,
    pub(crate) metric_for_comparison: ::std::option::Option<::std::string::String>,
    pub(crate) filter: ::std::option::Option<crate::types::Expression>,
    pub(crate) group_by: ::std::option::Option<::std::vec::Vec<crate::types::GroupDefinition>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
}
impl GetCostComparisonDriversInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies a specific billing view. The ARN is used to specify which particular billing view you want to interact with or retrieve information from when making API calls related to Amazon Web Services Billing and Cost Management features. The BillingViewArn can be retrieved by calling the ListBillingViews API.</p>
    pub fn billing_view_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.billing_view_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies a specific billing view. The ARN is used to specify which particular billing view you want to interact with or retrieve information from when making API calls related to Amazon Web Services Billing and Cost Management features. The BillingViewArn can be retrieved by calling the ListBillingViews API.</p>
    pub fn set_billing_view_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.billing_view_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies a specific billing view. The ARN is used to specify which particular billing view you want to interact with or retrieve information from when making API calls related to Amazon Web Services Billing and Cost Management features. The BillingViewArn can be retrieved by calling the ListBillingViews API.</p>
    pub fn get_billing_view_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.billing_view_arn
    }
    /// <p>The reference time period for comparison. This time period serves as the baseline against which other cost and usage data will be compared. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    /// This field is required.
    pub fn baseline_time_period(mut self, input: crate::types::DateInterval) -> Self {
        self.baseline_time_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reference time period for comparison. This time period serves as the baseline against which other cost and usage data will be compared. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub fn set_baseline_time_period(mut self, input: ::std::option::Option<crate::types::DateInterval>) -> Self {
        self.baseline_time_period = input;
        self
    }
    /// <p>The reference time period for comparison. This time period serves as the baseline against which other cost and usage data will be compared. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub fn get_baseline_time_period(&self) -> &::std::option::Option<crate::types::DateInterval> {
        &self.baseline_time_period
    }
    /// <p>The comparison time period for analysis. This time period's cost and usage data will be compared against the baseline time period. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    /// This field is required.
    pub fn comparison_time_period(mut self, input: crate::types::DateInterval) -> Self {
        self.comparison_time_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The comparison time period for analysis. This time period's cost and usage data will be compared against the baseline time period. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub fn set_comparison_time_period(mut self, input: ::std::option::Option<crate::types::DateInterval>) -> Self {
        self.comparison_time_period = input;
        self
    }
    /// <p>The comparison time period for analysis. This time period's cost and usage data will be compared against the baseline time period. The interval must start and end on the first day of a month, with a duration of exactly one month.</p>
    pub fn get_comparison_time_period(&self) -> &::std::option::Option<crate::types::DateInterval> {
        &self.comparison_time_period
    }
    /// <p>The cost and usage metric to compare. Valid values are <code>AmortizedCost</code>, <code>BlendedCost</code>, <code>NetAmortizedCost</code>, <code>NetUnblendedCost</code>, <code>NormalizedUsageAmount</code>, <code>UnblendedCost</code>, and <code>UsageQuantity</code>.</p>
    /// This field is required.
    pub fn metric_for_comparison(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric_for_comparison = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cost and usage metric to compare. Valid values are <code>AmortizedCost</code>, <code>BlendedCost</code>, <code>NetAmortizedCost</code>, <code>NetUnblendedCost</code>, <code>NormalizedUsageAmount</code>, <code>UnblendedCost</code>, and <code>UsageQuantity</code>.</p>
    pub fn set_metric_for_comparison(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric_for_comparison = input;
        self
    }
    /// <p>The cost and usage metric to compare. Valid values are <code>AmortizedCost</code>, <code>BlendedCost</code>, <code>NetAmortizedCost</code>, <code>NetUnblendedCost</code>, <code>NormalizedUsageAmount</code>, <code>UnblendedCost</code>, and <code>UsageQuantity</code>.</p>
    pub fn get_metric_for_comparison(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric_for_comparison
    }
    /// <p>Use <code>Expression</code> to filter in various Cost Explorer APIs.</p>
    /// <p>Not all <code>Expression</code> types are supported in each API. Refer to the documentation for each specific API to see what is supported.</p>
    /// <p>There are two patterns:</p>
    /// <ul>
    /// <li>
    /// <p>Simple dimension values.</p>
    /// <ul>
    /// <li>
    /// <p>There are three types of simple dimension values: <code>CostCategories</code>, <code>Tags</code>, and <code>Dimensions</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Specify the <code>CostCategories</code> field to define a filter that acts on Cost Categories.</p></li>
    /// <li>
    /// <p>Specify the <code>Tags</code> field to define a filter that acts on Cost Allocation Tags.</p></li>
    /// <li>
    /// <p>Specify the <code>Dimensions</code> field to define a filter that acts on the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_DimensionValues.html"> <code>DimensionValues</code> </a>.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For each filter type, you can set the dimension name and values for the filters that you plan to use.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for <code>REGION==us-east-1 OR REGION==us-west-1</code>. For <code>GetRightsizingRecommendation</code>, the Region is a full name (for example, <code>REGION==US East (N. Virginia)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] } }</code></p></li>
    /// <li>
    /// <p>As shown in the previous example, lists of dimension values are combined with <code>OR</code> when applying the filter.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>You can also set different match options to further control how the filter behaves. Not all APIs support match options. Refer to the documentation for each specific API to see what is supported.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for linked account names that start with "a".</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "LINKED_ACCOUNT_NAME", "MatchOptions": \[ "STARTS_WITH" \], "Values": \[ "a" \] } }</code></p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p>Compound <code>Expression</code> types with logical operations.</p>
    /// <ul>
    /// <li>
    /// <p>You can use multiple <code>Expression</code> types and the logical operators <code>AND/OR/NOT</code> to create a list of one or more <code>Expression</code> objects. By doing this, you can filter by more advanced options.</p></li>
    /// <li>
    /// <p>For example, you can filter by <code>((REGION == us-east-1 OR REGION == us-west-1) OR (TAG.Type == Type1)) AND (USAGE_TYPE != DataTransfer)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "And": \[ {"Or": \[ {"Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] }}, {"Tags": { "Key": "TagName", "Values": \["Value1"\] } } \]}, {"Not": {"Dimensions": { "Key": "USAGE_TYPE", "Values": \["DataTransfer"\] }}} \] }</code></p></li>
    /// </ul><note>
    /// <p>Because each <code>Expression</code> can have only one operator, the service returns an error if more than one is specified. The following example shows an <code>Expression</code> object that creates an error: <code>{ "And": \[ ... \], "Dimensions": { "Key": "USAGE_TYPE", "Values": \[ "DataTransfer" \] } }</code></p>
    /// <p>The following is an example of the corresponding error message: <code>"Expression has more than one roots. Only one root operator is allowed for each expression: And, Or, Not, Dimensions, Tags, CostCategories"</code></p>
    /// </note></li>
    /// </ul><note>
    /// <p>For the <code>GetRightsizingRecommendation</code> action, a combination of OR and NOT isn't supported. OR isn't supported between different dimensions, or dimensions and tags. NOT operators aren't supported. Dimensions are also limited to <code>LINKED_ACCOUNT</code>, <code>REGION</code>, or <code>RIGHTSIZING_TYPE</code>.</p>
    /// <p>For the <code>GetReservationPurchaseRecommendation</code> action, only NOT is supported. AND and OR aren't supported. Dimensions are limited to <code>LINKED_ACCOUNT</code>.</p>
    /// </note>
    pub fn filter(mut self, input: crate::types::Expression) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use <code>Expression</code> to filter in various Cost Explorer APIs.</p>
    /// <p>Not all <code>Expression</code> types are supported in each API. Refer to the documentation for each specific API to see what is supported.</p>
    /// <p>There are two patterns:</p>
    /// <ul>
    /// <li>
    /// <p>Simple dimension values.</p>
    /// <ul>
    /// <li>
    /// <p>There are three types of simple dimension values: <code>CostCategories</code>, <code>Tags</code>, and <code>Dimensions</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Specify the <code>CostCategories</code> field to define a filter that acts on Cost Categories.</p></li>
    /// <li>
    /// <p>Specify the <code>Tags</code> field to define a filter that acts on Cost Allocation Tags.</p></li>
    /// <li>
    /// <p>Specify the <code>Dimensions</code> field to define a filter that acts on the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_DimensionValues.html"> <code>DimensionValues</code> </a>.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For each filter type, you can set the dimension name and values for the filters that you plan to use.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for <code>REGION==us-east-1 OR REGION==us-west-1</code>. For <code>GetRightsizingRecommendation</code>, the Region is a full name (for example, <code>REGION==US East (N. Virginia)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] } }</code></p></li>
    /// <li>
    /// <p>As shown in the previous example, lists of dimension values are combined with <code>OR</code> when applying the filter.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>You can also set different match options to further control how the filter behaves. Not all APIs support match options. Refer to the documentation for each specific API to see what is supported.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for linked account names that start with "a".</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "LINKED_ACCOUNT_NAME", "MatchOptions": \[ "STARTS_WITH" \], "Values": \[ "a" \] } }</code></p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p>Compound <code>Expression</code> types with logical operations.</p>
    /// <ul>
    /// <li>
    /// <p>You can use multiple <code>Expression</code> types and the logical operators <code>AND/OR/NOT</code> to create a list of one or more <code>Expression</code> objects. By doing this, you can filter by more advanced options.</p></li>
    /// <li>
    /// <p>For example, you can filter by <code>((REGION == us-east-1 OR REGION == us-west-1) OR (TAG.Type == Type1)) AND (USAGE_TYPE != DataTransfer)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "And": \[ {"Or": \[ {"Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] }}, {"Tags": { "Key": "TagName", "Values": \["Value1"\] } } \]}, {"Not": {"Dimensions": { "Key": "USAGE_TYPE", "Values": \["DataTransfer"\] }}} \] }</code></p></li>
    /// </ul><note>
    /// <p>Because each <code>Expression</code> can have only one operator, the service returns an error if more than one is specified. The following example shows an <code>Expression</code> object that creates an error: <code>{ "And": \[ ... \], "Dimensions": { "Key": "USAGE_TYPE", "Values": \[ "DataTransfer" \] } }</code></p>
    /// <p>The following is an example of the corresponding error message: <code>"Expression has more than one roots. Only one root operator is allowed for each expression: And, Or, Not, Dimensions, Tags, CostCategories"</code></p>
    /// </note></li>
    /// </ul><note>
    /// <p>For the <code>GetRightsizingRecommendation</code> action, a combination of OR and NOT isn't supported. OR isn't supported between different dimensions, or dimensions and tags. NOT operators aren't supported. Dimensions are also limited to <code>LINKED_ACCOUNT</code>, <code>REGION</code>, or <code>RIGHTSIZING_TYPE</code>.</p>
    /// <p>For the <code>GetReservationPurchaseRecommendation</code> action, only NOT is supported. AND and OR aren't supported. Dimensions are limited to <code>LINKED_ACCOUNT</code>.</p>
    /// </note>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::Expression>) -> Self {
        self.filter = input;
        self
    }
    /// <p>Use <code>Expression</code> to filter in various Cost Explorer APIs.</p>
    /// <p>Not all <code>Expression</code> types are supported in each API. Refer to the documentation for each specific API to see what is supported.</p>
    /// <p>There are two patterns:</p>
    /// <ul>
    /// <li>
    /// <p>Simple dimension values.</p>
    /// <ul>
    /// <li>
    /// <p>There are three types of simple dimension values: <code>CostCategories</code>, <code>Tags</code>, and <code>Dimensions</code>.</p>
    /// <ul>
    /// <li>
    /// <p>Specify the <code>CostCategories</code> field to define a filter that acts on Cost Categories.</p></li>
    /// <li>
    /// <p>Specify the <code>Tags</code> field to define a filter that acts on Cost Allocation Tags.</p></li>
    /// <li>
    /// <p>Specify the <code>Dimensions</code> field to define a filter that acts on the <a href="https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_DimensionValues.html"> <code>DimensionValues</code> </a>.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For each filter type, you can set the dimension name and values for the filters that you plan to use.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for <code>REGION==us-east-1 OR REGION==us-west-1</code>. For <code>GetRightsizingRecommendation</code>, the Region is a full name (for example, <code>REGION==US East (N. Virginia)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] } }</code></p></li>
    /// <li>
    /// <p>As shown in the previous example, lists of dimension values are combined with <code>OR</code> when applying the filter.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>You can also set different match options to further control how the filter behaves. Not all APIs support match options. Refer to the documentation for each specific API to see what is supported.</p>
    /// <ul>
    /// <li>
    /// <p>For example, you can filter for linked account names that start with "a".</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "Dimensions": { "Key": "LINKED_ACCOUNT_NAME", "MatchOptions": \[ "STARTS_WITH" \], "Values": \[ "a" \] } }</code></p></li>
    /// </ul></li>
    /// </ul></li>
    /// <li>
    /// <p>Compound <code>Expression</code> types with logical operations.</p>
    /// <ul>
    /// <li>
    /// <p>You can use multiple <code>Expression</code> types and the logical operators <code>AND/OR/NOT</code> to create a list of one or more <code>Expression</code> objects. By doing this, you can filter by more advanced options.</p></li>
    /// <li>
    /// <p>For example, you can filter by <code>((REGION == us-east-1 OR REGION == us-west-1) OR (TAG.Type == Type1)) AND (USAGE_TYPE != DataTransfer)</code>.</p></li>
    /// <li>
    /// <p>The corresponding <code>Expression</code> for this example is as follows: <code>{ "And": \[ {"Or": \[ {"Dimensions": { "Key": "REGION", "Values": \[ "us-east-1", "us-west-1" \] }}, {"Tags": { "Key": "TagName", "Values": \["Value1"\] } } \]}, {"Not": {"Dimensions": { "Key": "USAGE_TYPE", "Values": \["DataTransfer"\] }}} \] }</code></p></li>
    /// </ul><note>
    /// <p>Because each <code>Expression</code> can have only one operator, the service returns an error if more than one is specified. The following example shows an <code>Expression</code> object that creates an error: <code>{ "And": \[ ... \], "Dimensions": { "Key": "USAGE_TYPE", "Values": \[ "DataTransfer" \] } }</code></p>
    /// <p>The following is an example of the corresponding error message: <code>"Expression has more than one roots. Only one root operator is allowed for each expression: And, Or, Not, Dimensions, Tags, CostCategories"</code></p>
    /// </note></li>
    /// </ul><note>
    /// <p>For the <code>GetRightsizingRecommendation</code> action, a combination of OR and NOT isn't supported. OR isn't supported between different dimensions, or dimensions and tags. NOT operators aren't supported. Dimensions are also limited to <code>LINKED_ACCOUNT</code>, <code>REGION</code>, or <code>RIGHTSIZING_TYPE</code>.</p>
    /// <p>For the <code>GetReservationPurchaseRecommendation</code> action, only NOT is supported. AND and OR aren't supported. Dimensions are limited to <code>LINKED_ACCOUNT</code>.</p>
    /// </note>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::Expression> {
        &self.filter
    }
    /// Appends an item to `group_by`.
    ///
    /// To override the contents of this collection use [`set_group_by`](Self::set_group_by).
    ///
    /// <p>You can group results using the attributes <code>DIMENSION</code>, <code>TAG</code>, and <code>COST_CATEGORY</code>. Note that <code>SERVICE</code> and <code>USAGE_TYPE</code> dimensions are automatically included in the cost comparison drivers analysis.</p>
    pub fn group_by(mut self, input: crate::types::GroupDefinition) -> Self {
        let mut v = self.group_by.unwrap_or_default();
        v.push(input);
        self.group_by = ::std::option::Option::Some(v);
        self
    }
    /// <p>You can group results using the attributes <code>DIMENSION</code>, <code>TAG</code>, and <code>COST_CATEGORY</code>. Note that <code>SERVICE</code> and <code>USAGE_TYPE</code> dimensions are automatically included in the cost comparison drivers analysis.</p>
    pub fn set_group_by(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GroupDefinition>>) -> Self {
        self.group_by = input;
        self
    }
    /// <p>You can group results using the attributes <code>DIMENSION</code>, <code>TAG</code>, and <code>COST_CATEGORY</code>. Note that <code>SERVICE</code> and <code>USAGE_TYPE</code> dimensions are automatically included in the cost comparison drivers analysis.</p>
    pub fn get_group_by(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GroupDefinition>> {
        &self.group_by
    }
    /// <p>The maximum number of results that are returned for the request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that are returned for the request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that are returned for the request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token to retrieve the next set of paginated results.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next set of paginated results.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The token to retrieve the next set of paginated results.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    /// Consumes the builder and constructs a [`GetCostComparisonDriversInput`](crate::operation::get_cost_comparison_drivers::GetCostComparisonDriversInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_cost_comparison_drivers::GetCostComparisonDriversInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_cost_comparison_drivers::GetCostComparisonDriversInput {
            billing_view_arn: self.billing_view_arn,
            baseline_time_period: self.baseline_time_period,
            comparison_time_period: self.comparison_time_period,
            metric_for_comparison: self.metric_for_comparison,
            filter: self.filter,
            group_by: self.group_by,
            max_results: self.max_results,
            next_page_token: self.next_page_token,
        })
    }
}
