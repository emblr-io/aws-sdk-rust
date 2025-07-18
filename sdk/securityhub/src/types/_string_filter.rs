// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A string filter for filtering Security Hub findings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StringFilter {
    /// <p>The string filter value. Filter values are case sensitive. For example, the product name for control-based findings is <code>Security Hub</code>. If you provide <code>security hub</code> as the filter value, there's no match.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>The condition to apply to a string value when filtering Security Hub findings.</p>
    /// <p>To search for values that have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that include the filter value, use <code>CONTAINS</code>. For example, the filter <code>Title CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that includes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values that exactly match the filter value, use <code>EQUALS</code>. For example, the filter <code>AwsAccountId EQUALS 123456789012</code> only matches findings that have an account ID of <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that start with the filter value, use <code>PREFIX</code>. For example, the filter <code>ResourceRegion PREFIX us</code> matches findings that have a <code>ResourceRegion</code> that starts with <code>us</code>. A <code>ResourceRegion</code> that starts with a different value, such as <code>af</code>, <code>ap</code>, or <code>ca</code>, doesn't match.</p></li>
    /// </ul>
    /// <p><code>CONTAINS</code>, <code>EQUALS</code>, and <code>PREFIX</code> filters on the same field are joined by <code>OR</code>. A finding matches if it matches any one of those filters. For example, the filters <code>Title CONTAINS CloudFront OR Title CONTAINS CloudWatch</code> match a finding that includes either <code>CloudFront</code>, <code>CloudWatch</code>, or both strings in the title.</p>
    /// <p>To search for values that don’t have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that exclude the filter value, use <code>NOT_CONTAINS</code>. For example, the filter <code>Title NOT_CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that excludes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values other than the filter value, use <code>NOT_EQUALS</code>. For example, the filter <code>AwsAccountId NOT_EQUALS 123456789012</code> only matches findings that have an account ID other than <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that don't start with the filter value, use <code>PREFIX_NOT_EQUALS</code>. For example, the filter <code>ResourceRegion PREFIX_NOT_EQUALS us</code> matches findings with a <code>ResourceRegion</code> that starts with a value other than <code>us</code>.</p></li>
    /// </ul>
    /// <p><code>NOT_CONTAINS</code>, <code>NOT_EQUALS</code>, and <code>PREFIX_NOT_EQUALS</code> filters on the same field are joined by <code>AND</code>. A finding matches only if it matches all of those filters. For example, the filters <code>Title NOT_CONTAINS CloudFront AND Title NOT_CONTAINS CloudWatch</code> match a finding that excludes both <code>CloudFront</code> and <code>CloudWatch</code> in the title.</p>
    /// <p>You can’t have both a <code>CONTAINS</code> filter and a <code>NOT_CONTAINS</code> filter on the same field. Similarly, you can't provide both an <code>EQUALS</code> filter and a <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filter on the same field. Combining filters in this way returns an error. <code>CONTAINS</code> filters can only be used with other <code>CONTAINS</code> filters. <code>NOT_CONTAINS</code> filters can only be used with other <code>NOT_CONTAINS</code> filters.</p>
    /// <p>You can combine <code>PREFIX</code> filters with <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters for the same field. Security Hub first processes the <code>PREFIX</code> filters, and then the <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters.</p>
    /// <p>For example, for the following filters, Security Hub first identifies findings that have resource types that start with either <code>AwsIam</code> or <code>AwsEc2</code>. It then excludes findings that have a resource type of <code>AwsIamPolicy</code> and findings that have a resource type of <code>AwsEc2NetworkInterface</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsIam</code></p></li>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsEc2</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsIamPolicy</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsEc2NetworkInterface</code></p></li>
    /// </ul>
    /// <p><code>CONTAINS</code> and <code>NOT_CONTAINS</code> operators can be used only with automation rules V1. <code>CONTAINS_WORD</code> operator is only supported in <code>GetFindingsV2</code>, <code>GetFindingStatisticsV2</code>, <code>GetResourcesV2</code>, and <code>GetResourceStatisticsV2</code> APIs. For more information, see <a href="https://docs.aws.amazon.com/securityhub/latest/userguide/automation-rules.html">Automation rules</a> in the <i>Security Hub User Guide</i>.</p>
    pub comparison: ::std::option::Option<crate::types::StringFilterComparison>,
}
impl StringFilter {
    /// <p>The string filter value. Filter values are case sensitive. For example, the product name for control-based findings is <code>Security Hub</code>. If you provide <code>security hub</code> as the filter value, there's no match.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>The condition to apply to a string value when filtering Security Hub findings.</p>
    /// <p>To search for values that have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that include the filter value, use <code>CONTAINS</code>. For example, the filter <code>Title CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that includes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values that exactly match the filter value, use <code>EQUALS</code>. For example, the filter <code>AwsAccountId EQUALS 123456789012</code> only matches findings that have an account ID of <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that start with the filter value, use <code>PREFIX</code>. For example, the filter <code>ResourceRegion PREFIX us</code> matches findings that have a <code>ResourceRegion</code> that starts with <code>us</code>. A <code>ResourceRegion</code> that starts with a different value, such as <code>af</code>, <code>ap</code>, or <code>ca</code>, doesn't match.</p></li>
    /// </ul>
    /// <p><code>CONTAINS</code>, <code>EQUALS</code>, and <code>PREFIX</code> filters on the same field are joined by <code>OR</code>. A finding matches if it matches any one of those filters. For example, the filters <code>Title CONTAINS CloudFront OR Title CONTAINS CloudWatch</code> match a finding that includes either <code>CloudFront</code>, <code>CloudWatch</code>, or both strings in the title.</p>
    /// <p>To search for values that don’t have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that exclude the filter value, use <code>NOT_CONTAINS</code>. For example, the filter <code>Title NOT_CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that excludes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values other than the filter value, use <code>NOT_EQUALS</code>. For example, the filter <code>AwsAccountId NOT_EQUALS 123456789012</code> only matches findings that have an account ID other than <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that don't start with the filter value, use <code>PREFIX_NOT_EQUALS</code>. For example, the filter <code>ResourceRegion PREFIX_NOT_EQUALS us</code> matches findings with a <code>ResourceRegion</code> that starts with a value other than <code>us</code>.</p></li>
    /// </ul>
    /// <p><code>NOT_CONTAINS</code>, <code>NOT_EQUALS</code>, and <code>PREFIX_NOT_EQUALS</code> filters on the same field are joined by <code>AND</code>. A finding matches only if it matches all of those filters. For example, the filters <code>Title NOT_CONTAINS CloudFront AND Title NOT_CONTAINS CloudWatch</code> match a finding that excludes both <code>CloudFront</code> and <code>CloudWatch</code> in the title.</p>
    /// <p>You can’t have both a <code>CONTAINS</code> filter and a <code>NOT_CONTAINS</code> filter on the same field. Similarly, you can't provide both an <code>EQUALS</code> filter and a <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filter on the same field. Combining filters in this way returns an error. <code>CONTAINS</code> filters can only be used with other <code>CONTAINS</code> filters. <code>NOT_CONTAINS</code> filters can only be used with other <code>NOT_CONTAINS</code> filters.</p>
    /// <p>You can combine <code>PREFIX</code> filters with <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters for the same field. Security Hub first processes the <code>PREFIX</code> filters, and then the <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters.</p>
    /// <p>For example, for the following filters, Security Hub first identifies findings that have resource types that start with either <code>AwsIam</code> or <code>AwsEc2</code>. It then excludes findings that have a resource type of <code>AwsIamPolicy</code> and findings that have a resource type of <code>AwsEc2NetworkInterface</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsIam</code></p></li>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsEc2</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsIamPolicy</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsEc2NetworkInterface</code></p></li>
    /// </ul>
    /// <p><code>CONTAINS</code> and <code>NOT_CONTAINS</code> operators can be used only with automation rules V1. <code>CONTAINS_WORD</code> operator is only supported in <code>GetFindingsV2</code>, <code>GetFindingStatisticsV2</code>, <code>GetResourcesV2</code>, and <code>GetResourceStatisticsV2</code> APIs. For more information, see <a href="https://docs.aws.amazon.com/securityhub/latest/userguide/automation-rules.html">Automation rules</a> in the <i>Security Hub User Guide</i>.</p>
    pub fn comparison(&self) -> ::std::option::Option<&crate::types::StringFilterComparison> {
        self.comparison.as_ref()
    }
}
impl StringFilter {
    /// Creates a new builder-style object to manufacture [`StringFilter`](crate::types::StringFilter).
    pub fn builder() -> crate::types::builders::StringFilterBuilder {
        crate::types::builders::StringFilterBuilder::default()
    }
}

/// A builder for [`StringFilter`](crate::types::StringFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StringFilterBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) comparison: ::std::option::Option<crate::types::StringFilterComparison>,
}
impl StringFilterBuilder {
    /// <p>The string filter value. Filter values are case sensitive. For example, the product name for control-based findings is <code>Security Hub</code>. If you provide <code>security hub</code> as the filter value, there's no match.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string filter value. Filter values are case sensitive. For example, the product name for control-based findings is <code>Security Hub</code>. If you provide <code>security hub</code> as the filter value, there's no match.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The string filter value. Filter values are case sensitive. For example, the product name for control-based findings is <code>Security Hub</code>. If you provide <code>security hub</code> as the filter value, there's no match.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The condition to apply to a string value when filtering Security Hub findings.</p>
    /// <p>To search for values that have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that include the filter value, use <code>CONTAINS</code>. For example, the filter <code>Title CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that includes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values that exactly match the filter value, use <code>EQUALS</code>. For example, the filter <code>AwsAccountId EQUALS 123456789012</code> only matches findings that have an account ID of <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that start with the filter value, use <code>PREFIX</code>. For example, the filter <code>ResourceRegion PREFIX us</code> matches findings that have a <code>ResourceRegion</code> that starts with <code>us</code>. A <code>ResourceRegion</code> that starts with a different value, such as <code>af</code>, <code>ap</code>, or <code>ca</code>, doesn't match.</p></li>
    /// </ul>
    /// <p><code>CONTAINS</code>, <code>EQUALS</code>, and <code>PREFIX</code> filters on the same field are joined by <code>OR</code>. A finding matches if it matches any one of those filters. For example, the filters <code>Title CONTAINS CloudFront OR Title CONTAINS CloudWatch</code> match a finding that includes either <code>CloudFront</code>, <code>CloudWatch</code>, or both strings in the title.</p>
    /// <p>To search for values that don’t have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that exclude the filter value, use <code>NOT_CONTAINS</code>. For example, the filter <code>Title NOT_CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that excludes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values other than the filter value, use <code>NOT_EQUALS</code>. For example, the filter <code>AwsAccountId NOT_EQUALS 123456789012</code> only matches findings that have an account ID other than <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that don't start with the filter value, use <code>PREFIX_NOT_EQUALS</code>. For example, the filter <code>ResourceRegion PREFIX_NOT_EQUALS us</code> matches findings with a <code>ResourceRegion</code> that starts with a value other than <code>us</code>.</p></li>
    /// </ul>
    /// <p><code>NOT_CONTAINS</code>, <code>NOT_EQUALS</code>, and <code>PREFIX_NOT_EQUALS</code> filters on the same field are joined by <code>AND</code>. A finding matches only if it matches all of those filters. For example, the filters <code>Title NOT_CONTAINS CloudFront AND Title NOT_CONTAINS CloudWatch</code> match a finding that excludes both <code>CloudFront</code> and <code>CloudWatch</code> in the title.</p>
    /// <p>You can’t have both a <code>CONTAINS</code> filter and a <code>NOT_CONTAINS</code> filter on the same field. Similarly, you can't provide both an <code>EQUALS</code> filter and a <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filter on the same field. Combining filters in this way returns an error. <code>CONTAINS</code> filters can only be used with other <code>CONTAINS</code> filters. <code>NOT_CONTAINS</code> filters can only be used with other <code>NOT_CONTAINS</code> filters.</p>
    /// <p>You can combine <code>PREFIX</code> filters with <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters for the same field. Security Hub first processes the <code>PREFIX</code> filters, and then the <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters.</p>
    /// <p>For example, for the following filters, Security Hub first identifies findings that have resource types that start with either <code>AwsIam</code> or <code>AwsEc2</code>. It then excludes findings that have a resource type of <code>AwsIamPolicy</code> and findings that have a resource type of <code>AwsEc2NetworkInterface</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsIam</code></p></li>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsEc2</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsIamPolicy</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsEc2NetworkInterface</code></p></li>
    /// </ul>
    /// <p><code>CONTAINS</code> and <code>NOT_CONTAINS</code> operators can be used only with automation rules V1. <code>CONTAINS_WORD</code> operator is only supported in <code>GetFindingsV2</code>, <code>GetFindingStatisticsV2</code>, <code>GetResourcesV2</code>, and <code>GetResourceStatisticsV2</code> APIs. For more information, see <a href="https://docs.aws.amazon.com/securityhub/latest/userguide/automation-rules.html">Automation rules</a> in the <i>Security Hub User Guide</i>.</p>
    pub fn comparison(mut self, input: crate::types::StringFilterComparison) -> Self {
        self.comparison = ::std::option::Option::Some(input);
        self
    }
    /// <p>The condition to apply to a string value when filtering Security Hub findings.</p>
    /// <p>To search for values that have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that include the filter value, use <code>CONTAINS</code>. For example, the filter <code>Title CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that includes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values that exactly match the filter value, use <code>EQUALS</code>. For example, the filter <code>AwsAccountId EQUALS 123456789012</code> only matches findings that have an account ID of <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that start with the filter value, use <code>PREFIX</code>. For example, the filter <code>ResourceRegion PREFIX us</code> matches findings that have a <code>ResourceRegion</code> that starts with <code>us</code>. A <code>ResourceRegion</code> that starts with a different value, such as <code>af</code>, <code>ap</code>, or <code>ca</code>, doesn't match.</p></li>
    /// </ul>
    /// <p><code>CONTAINS</code>, <code>EQUALS</code>, and <code>PREFIX</code> filters on the same field are joined by <code>OR</code>. A finding matches if it matches any one of those filters. For example, the filters <code>Title CONTAINS CloudFront OR Title CONTAINS CloudWatch</code> match a finding that includes either <code>CloudFront</code>, <code>CloudWatch</code>, or both strings in the title.</p>
    /// <p>To search for values that don’t have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that exclude the filter value, use <code>NOT_CONTAINS</code>. For example, the filter <code>Title NOT_CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that excludes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values other than the filter value, use <code>NOT_EQUALS</code>. For example, the filter <code>AwsAccountId NOT_EQUALS 123456789012</code> only matches findings that have an account ID other than <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that don't start with the filter value, use <code>PREFIX_NOT_EQUALS</code>. For example, the filter <code>ResourceRegion PREFIX_NOT_EQUALS us</code> matches findings with a <code>ResourceRegion</code> that starts with a value other than <code>us</code>.</p></li>
    /// </ul>
    /// <p><code>NOT_CONTAINS</code>, <code>NOT_EQUALS</code>, and <code>PREFIX_NOT_EQUALS</code> filters on the same field are joined by <code>AND</code>. A finding matches only if it matches all of those filters. For example, the filters <code>Title NOT_CONTAINS CloudFront AND Title NOT_CONTAINS CloudWatch</code> match a finding that excludes both <code>CloudFront</code> and <code>CloudWatch</code> in the title.</p>
    /// <p>You can’t have both a <code>CONTAINS</code> filter and a <code>NOT_CONTAINS</code> filter on the same field. Similarly, you can't provide both an <code>EQUALS</code> filter and a <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filter on the same field. Combining filters in this way returns an error. <code>CONTAINS</code> filters can only be used with other <code>CONTAINS</code> filters. <code>NOT_CONTAINS</code> filters can only be used with other <code>NOT_CONTAINS</code> filters.</p>
    /// <p>You can combine <code>PREFIX</code> filters with <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters for the same field. Security Hub first processes the <code>PREFIX</code> filters, and then the <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters.</p>
    /// <p>For example, for the following filters, Security Hub first identifies findings that have resource types that start with either <code>AwsIam</code> or <code>AwsEc2</code>. It then excludes findings that have a resource type of <code>AwsIamPolicy</code> and findings that have a resource type of <code>AwsEc2NetworkInterface</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsIam</code></p></li>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsEc2</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsIamPolicy</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsEc2NetworkInterface</code></p></li>
    /// </ul>
    /// <p><code>CONTAINS</code> and <code>NOT_CONTAINS</code> operators can be used only with automation rules V1. <code>CONTAINS_WORD</code> operator is only supported in <code>GetFindingsV2</code>, <code>GetFindingStatisticsV2</code>, <code>GetResourcesV2</code>, and <code>GetResourceStatisticsV2</code> APIs. For more information, see <a href="https://docs.aws.amazon.com/securityhub/latest/userguide/automation-rules.html">Automation rules</a> in the <i>Security Hub User Guide</i>.</p>
    pub fn set_comparison(mut self, input: ::std::option::Option<crate::types::StringFilterComparison>) -> Self {
        self.comparison = input;
        self
    }
    /// <p>The condition to apply to a string value when filtering Security Hub findings.</p>
    /// <p>To search for values that have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that include the filter value, use <code>CONTAINS</code>. For example, the filter <code>Title CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that includes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values that exactly match the filter value, use <code>EQUALS</code>. For example, the filter <code>AwsAccountId EQUALS 123456789012</code> only matches findings that have an account ID of <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that start with the filter value, use <code>PREFIX</code>. For example, the filter <code>ResourceRegion PREFIX us</code> matches findings that have a <code>ResourceRegion</code> that starts with <code>us</code>. A <code>ResourceRegion</code> that starts with a different value, such as <code>af</code>, <code>ap</code>, or <code>ca</code>, doesn't match.</p></li>
    /// </ul>
    /// <p><code>CONTAINS</code>, <code>EQUALS</code>, and <code>PREFIX</code> filters on the same field are joined by <code>OR</code>. A finding matches if it matches any one of those filters. For example, the filters <code>Title CONTAINS CloudFront OR Title CONTAINS CloudWatch</code> match a finding that includes either <code>CloudFront</code>, <code>CloudWatch</code>, or both strings in the title.</p>
    /// <p>To search for values that don’t have the filter value, use one of the following comparison operators:</p>
    /// <ul>
    /// <li>
    /// <p>To search for values that exclude the filter value, use <code>NOT_CONTAINS</code>. For example, the filter <code>Title NOT_CONTAINS CloudFront</code> matches findings that have a <code>Title</code> that excludes the string CloudFront.</p></li>
    /// <li>
    /// <p>To search for values other than the filter value, use <code>NOT_EQUALS</code>. For example, the filter <code>AwsAccountId NOT_EQUALS 123456789012</code> only matches findings that have an account ID other than <code>123456789012</code>.</p></li>
    /// <li>
    /// <p>To search for values that don't start with the filter value, use <code>PREFIX_NOT_EQUALS</code>. For example, the filter <code>ResourceRegion PREFIX_NOT_EQUALS us</code> matches findings with a <code>ResourceRegion</code> that starts with a value other than <code>us</code>.</p></li>
    /// </ul>
    /// <p><code>NOT_CONTAINS</code>, <code>NOT_EQUALS</code>, and <code>PREFIX_NOT_EQUALS</code> filters on the same field are joined by <code>AND</code>. A finding matches only if it matches all of those filters. For example, the filters <code>Title NOT_CONTAINS CloudFront AND Title NOT_CONTAINS CloudWatch</code> match a finding that excludes both <code>CloudFront</code> and <code>CloudWatch</code> in the title.</p>
    /// <p>You can’t have both a <code>CONTAINS</code> filter and a <code>NOT_CONTAINS</code> filter on the same field. Similarly, you can't provide both an <code>EQUALS</code> filter and a <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filter on the same field. Combining filters in this way returns an error. <code>CONTAINS</code> filters can only be used with other <code>CONTAINS</code> filters. <code>NOT_CONTAINS</code> filters can only be used with other <code>NOT_CONTAINS</code> filters.</p>
    /// <p>You can combine <code>PREFIX</code> filters with <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters for the same field. Security Hub first processes the <code>PREFIX</code> filters, and then the <code>NOT_EQUALS</code> or <code>PREFIX_NOT_EQUALS</code> filters.</p>
    /// <p>For example, for the following filters, Security Hub first identifies findings that have resource types that start with either <code>AwsIam</code> or <code>AwsEc2</code>. It then excludes findings that have a resource type of <code>AwsIamPolicy</code> and findings that have a resource type of <code>AwsEc2NetworkInterface</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsIam</code></p></li>
    /// <li>
    /// <p><code>ResourceType PREFIX AwsEc2</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsIamPolicy</code></p></li>
    /// <li>
    /// <p><code>ResourceType NOT_EQUALS AwsEc2NetworkInterface</code></p></li>
    /// </ul>
    /// <p><code>CONTAINS</code> and <code>NOT_CONTAINS</code> operators can be used only with automation rules V1. <code>CONTAINS_WORD</code> operator is only supported in <code>GetFindingsV2</code>, <code>GetFindingStatisticsV2</code>, <code>GetResourcesV2</code>, and <code>GetResourceStatisticsV2</code> APIs. For more information, see <a href="https://docs.aws.amazon.com/securityhub/latest/userguide/automation-rules.html">Automation rules</a> in the <i>Security Hub User Guide</i>.</p>
    pub fn get_comparison(&self) -> &::std::option::Option<crate::types::StringFilterComparison> {
        &self.comparison
    }
    /// Consumes the builder and constructs a [`StringFilter`](crate::types::StringFilter).
    pub fn build(self) -> crate::types::StringFilter {
        crate::types::StringFilter {
            value: self.value,
            comparison: self.comparison,
        }
    }
}
