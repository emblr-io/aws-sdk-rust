// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartQueryInput {
    /// <p>The name of the monitor to query.</p>
    pub monitor_name: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp that is the beginning of the period that you want to retrieve data for with your query.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp that is the end of the period that you want to retrieve data for with your query.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The type of query to run. The following are the three types of queries that you can run using the Internet Monitor query interface:</p>
    /// <ul>
    /// <li>
    /// <p><code>MEASUREMENTS</code>: Provides availability score, performance score, total traffic, and round-trip times, at 5 minute intervals.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATIONS</code>: Provides availability score, performance score, total traffic, and time to first byte (TTFB) information, for the top location and ASN combinations that you're monitoring, by traffic volume.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATION_DETAILS</code>: Provides TTFB for Amazon CloudFront, your current configuration, and the best performing EC2 configuration, at 1 hour intervals.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS</code>: Provides TTFB, using a 30-day weighted average, for all traffic in each Amazon Web Services location that is monitored.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS_DETAILS</code>: Provides TTFB, using a 30-day weighted average, for each top location, for a proposed Amazon Web Services location. Must provide an Amazon Web Services location to search.</p></li>
    /// <li>
    /// <p><code>ROUTING_SUGGESTIONS</code>: Provides the predicted average round-trip time (RTT) from an IP prefix toward an Amazon Web Services location for a DNS resolver. The RTT is calculated at one hour intervals, over a one hour period.</p></li>
    /// </ul>
    /// <p>For lists of the fields returned with each query type and more information about how each type of query is performed, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html"> Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub query_type: ::std::option::Option<crate::types::QueryType>,
    /// <p>The <code>FilterParameters</code> field that you use with Amazon CloudWatch Internet Monitor queries is a string the defines how you want a query to be filtered. The filter parameters that you can specify depend on the query type, since each query type returns a different set of Internet Monitor data.</p>
    /// <p>For more information about specifying filter parameters, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html">Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub filter_parameters: ::std::option::Option<::std::vec::Vec<crate::types::FilterParameter>>,
    /// <p>The account ID for an account that you've set up cross-account sharing for in Amazon CloudWatch Internet Monitor. You configure cross-account sharing by using Amazon CloudWatch Observability Access Manager. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cwim-cross-account.html">Internet Monitor cross-account observability</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub linked_account_id: ::std::option::Option<::std::string::String>,
}
impl StartQueryInput {
    /// <p>The name of the monitor to query.</p>
    pub fn monitor_name(&self) -> ::std::option::Option<&str> {
        self.monitor_name.as_deref()
    }
    /// <p>The timestamp that is the beginning of the period that you want to retrieve data for with your query.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The timestamp that is the end of the period that you want to retrieve data for with your query.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The type of query to run. The following are the three types of queries that you can run using the Internet Monitor query interface:</p>
    /// <ul>
    /// <li>
    /// <p><code>MEASUREMENTS</code>: Provides availability score, performance score, total traffic, and round-trip times, at 5 minute intervals.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATIONS</code>: Provides availability score, performance score, total traffic, and time to first byte (TTFB) information, for the top location and ASN combinations that you're monitoring, by traffic volume.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATION_DETAILS</code>: Provides TTFB for Amazon CloudFront, your current configuration, and the best performing EC2 configuration, at 1 hour intervals.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS</code>: Provides TTFB, using a 30-day weighted average, for all traffic in each Amazon Web Services location that is monitored.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS_DETAILS</code>: Provides TTFB, using a 30-day weighted average, for each top location, for a proposed Amazon Web Services location. Must provide an Amazon Web Services location to search.</p></li>
    /// <li>
    /// <p><code>ROUTING_SUGGESTIONS</code>: Provides the predicted average round-trip time (RTT) from an IP prefix toward an Amazon Web Services location for a DNS resolver. The RTT is calculated at one hour intervals, over a one hour period.</p></li>
    /// </ul>
    /// <p>For lists of the fields returned with each query type and more information about how each type of query is performed, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html"> Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn query_type(&self) -> ::std::option::Option<&crate::types::QueryType> {
        self.query_type.as_ref()
    }
    /// <p>The <code>FilterParameters</code> field that you use with Amazon CloudWatch Internet Monitor queries is a string the defines how you want a query to be filtered. The filter parameters that you can specify depend on the query type, since each query type returns a different set of Internet Monitor data.</p>
    /// <p>For more information about specifying filter parameters, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html">Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filter_parameters.is_none()`.
    pub fn filter_parameters(&self) -> &[crate::types::FilterParameter] {
        self.filter_parameters.as_deref().unwrap_or_default()
    }
    /// <p>The account ID for an account that you've set up cross-account sharing for in Amazon CloudWatch Internet Monitor. You configure cross-account sharing by using Amazon CloudWatch Observability Access Manager. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cwim-cross-account.html">Internet Monitor cross-account observability</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn linked_account_id(&self) -> ::std::option::Option<&str> {
        self.linked_account_id.as_deref()
    }
}
impl StartQueryInput {
    /// Creates a new builder-style object to manufacture [`StartQueryInput`](crate::operation::start_query::StartQueryInput).
    pub fn builder() -> crate::operation::start_query::builders::StartQueryInputBuilder {
        crate::operation::start_query::builders::StartQueryInputBuilder::default()
    }
}

/// A builder for [`StartQueryInput`](crate::operation::start_query::StartQueryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartQueryInputBuilder {
    pub(crate) monitor_name: ::std::option::Option<::std::string::String>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) query_type: ::std::option::Option<crate::types::QueryType>,
    pub(crate) filter_parameters: ::std::option::Option<::std::vec::Vec<crate::types::FilterParameter>>,
    pub(crate) linked_account_id: ::std::option::Option<::std::string::String>,
}
impl StartQueryInputBuilder {
    /// <p>The name of the monitor to query.</p>
    /// This field is required.
    pub fn monitor_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.monitor_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the monitor to query.</p>
    pub fn set_monitor_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.monitor_name = input;
        self
    }
    /// <p>The name of the monitor to query.</p>
    pub fn get_monitor_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.monitor_name
    }
    /// <p>The timestamp that is the beginning of the period that you want to retrieve data for with your query.</p>
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that is the beginning of the period that you want to retrieve data for with your query.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The timestamp that is the beginning of the period that you want to retrieve data for with your query.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The timestamp that is the end of the period that you want to retrieve data for with your query.</p>
    /// This field is required.
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp that is the end of the period that you want to retrieve data for with your query.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The timestamp that is the end of the period that you want to retrieve data for with your query.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The type of query to run. The following are the three types of queries that you can run using the Internet Monitor query interface:</p>
    /// <ul>
    /// <li>
    /// <p><code>MEASUREMENTS</code>: Provides availability score, performance score, total traffic, and round-trip times, at 5 minute intervals.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATIONS</code>: Provides availability score, performance score, total traffic, and time to first byte (TTFB) information, for the top location and ASN combinations that you're monitoring, by traffic volume.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATION_DETAILS</code>: Provides TTFB for Amazon CloudFront, your current configuration, and the best performing EC2 configuration, at 1 hour intervals.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS</code>: Provides TTFB, using a 30-day weighted average, for all traffic in each Amazon Web Services location that is monitored.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS_DETAILS</code>: Provides TTFB, using a 30-day weighted average, for each top location, for a proposed Amazon Web Services location. Must provide an Amazon Web Services location to search.</p></li>
    /// <li>
    /// <p><code>ROUTING_SUGGESTIONS</code>: Provides the predicted average round-trip time (RTT) from an IP prefix toward an Amazon Web Services location for a DNS resolver. The RTT is calculated at one hour intervals, over a one hour period.</p></li>
    /// </ul>
    /// <p>For lists of the fields returned with each query type and more information about how each type of query is performed, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html"> Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    /// This field is required.
    pub fn query_type(mut self, input: crate::types::QueryType) -> Self {
        self.query_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of query to run. The following are the three types of queries that you can run using the Internet Monitor query interface:</p>
    /// <ul>
    /// <li>
    /// <p><code>MEASUREMENTS</code>: Provides availability score, performance score, total traffic, and round-trip times, at 5 minute intervals.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATIONS</code>: Provides availability score, performance score, total traffic, and time to first byte (TTFB) information, for the top location and ASN combinations that you're monitoring, by traffic volume.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATION_DETAILS</code>: Provides TTFB for Amazon CloudFront, your current configuration, and the best performing EC2 configuration, at 1 hour intervals.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS</code>: Provides TTFB, using a 30-day weighted average, for all traffic in each Amazon Web Services location that is monitored.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS_DETAILS</code>: Provides TTFB, using a 30-day weighted average, for each top location, for a proposed Amazon Web Services location. Must provide an Amazon Web Services location to search.</p></li>
    /// <li>
    /// <p><code>ROUTING_SUGGESTIONS</code>: Provides the predicted average round-trip time (RTT) from an IP prefix toward an Amazon Web Services location for a DNS resolver. The RTT is calculated at one hour intervals, over a one hour period.</p></li>
    /// </ul>
    /// <p>For lists of the fields returned with each query type and more information about how each type of query is performed, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html"> Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn set_query_type(mut self, input: ::std::option::Option<crate::types::QueryType>) -> Self {
        self.query_type = input;
        self
    }
    /// <p>The type of query to run. The following are the three types of queries that you can run using the Internet Monitor query interface:</p>
    /// <ul>
    /// <li>
    /// <p><code>MEASUREMENTS</code>: Provides availability score, performance score, total traffic, and round-trip times, at 5 minute intervals.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATIONS</code>: Provides availability score, performance score, total traffic, and time to first byte (TTFB) information, for the top location and ASN combinations that you're monitoring, by traffic volume.</p></li>
    /// <li>
    /// <p><code>TOP_LOCATION_DETAILS</code>: Provides TTFB for Amazon CloudFront, your current configuration, and the best performing EC2 configuration, at 1 hour intervals.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS</code>: Provides TTFB, using a 30-day weighted average, for all traffic in each Amazon Web Services location that is monitored.</p></li>
    /// <li>
    /// <p><code>OVERALL_TRAFFIC_SUGGESTIONS_DETAILS</code>: Provides TTFB, using a 30-day weighted average, for each top location, for a proposed Amazon Web Services location. Must provide an Amazon Web Services location to search.</p></li>
    /// <li>
    /// <p><code>ROUTING_SUGGESTIONS</code>: Provides the predicted average round-trip time (RTT) from an IP prefix toward an Amazon Web Services location for a DNS resolver. The RTT is calculated at one hour intervals, over a one hour period.</p></li>
    /// </ul>
    /// <p>For lists of the fields returned with each query type and more information about how each type of query is performed, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html"> Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn get_query_type(&self) -> &::std::option::Option<crate::types::QueryType> {
        &self.query_type
    }
    /// Appends an item to `filter_parameters`.
    ///
    /// To override the contents of this collection use [`set_filter_parameters`](Self::set_filter_parameters).
    ///
    /// <p>The <code>FilterParameters</code> field that you use with Amazon CloudWatch Internet Monitor queries is a string the defines how you want a query to be filtered. The filter parameters that you can specify depend on the query type, since each query type returns a different set of Internet Monitor data.</p>
    /// <p>For more information about specifying filter parameters, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html">Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn filter_parameters(mut self, input: crate::types::FilterParameter) -> Self {
        let mut v = self.filter_parameters.unwrap_or_default();
        v.push(input);
        self.filter_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <code>FilterParameters</code> field that you use with Amazon CloudWatch Internet Monitor queries is a string the defines how you want a query to be filtered. The filter parameters that you can specify depend on the query type, since each query type returns a different set of Internet Monitor data.</p>
    /// <p>For more information about specifying filter parameters, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html">Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn set_filter_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FilterParameter>>) -> Self {
        self.filter_parameters = input;
        self
    }
    /// <p>The <code>FilterParameters</code> field that you use with Amazon CloudWatch Internet Monitor queries is a string the defines how you want a query to be filtered. The filter parameters that you can specify depend on the query type, since each query type returns a different set of Internet Monitor data.</p>
    /// <p>For more information about specifying filter parameters, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-IM-view-cw-tools-cwim-query.html">Using the Amazon CloudWatch Internet Monitor query interface</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn get_filter_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilterParameter>> {
        &self.filter_parameters
    }
    /// <p>The account ID for an account that you've set up cross-account sharing for in Amazon CloudWatch Internet Monitor. You configure cross-account sharing by using Amazon CloudWatch Observability Access Manager. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cwim-cross-account.html">Internet Monitor cross-account observability</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn linked_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.linked_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID for an account that you've set up cross-account sharing for in Amazon CloudWatch Internet Monitor. You configure cross-account sharing by using Amazon CloudWatch Observability Access Manager. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cwim-cross-account.html">Internet Monitor cross-account observability</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn set_linked_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.linked_account_id = input;
        self
    }
    /// <p>The account ID for an account that you've set up cross-account sharing for in Amazon CloudWatch Internet Monitor. You configure cross-account sharing by using Amazon CloudWatch Observability Access Manager. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cwim-cross-account.html">Internet Monitor cross-account observability</a> in the Amazon CloudWatch Internet Monitor User Guide.</p>
    pub fn get_linked_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.linked_account_id
    }
    /// Consumes the builder and constructs a [`StartQueryInput`](crate::operation::start_query::StartQueryInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::start_query::StartQueryInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_query::StartQueryInput {
            monitor_name: self.monitor_name,
            start_time: self.start_time,
            end_time: self.end_time,
            query_type: self.query_type,
            filter_parameters: self.filter_parameters,
            linked_account_id: self.linked_account_id,
        })
    }
}
