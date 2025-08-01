// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLoggingConfigurationsInput {
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub scope: ::std::option::Option<crate::types::Scope>,
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of objects that you want WAF to return for this request. If more objects are available, in the response, WAF provides a <code>NextMarker</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>The owner of the logging configuration, which must be set to <code>CUSTOMER</code> for the configurations that you manage.</p>
    /// <p>The log scope <code>SECURITY_LAKE</code> indicates a configuration that is managed through Amazon Security Lake. You can use Security Lake to collect log and event data from various sources for normalization, analysis, and management. For information, see <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html">Collecting data from Amazon Web Services services</a> in the <i>Amazon Security Lake user guide</i>.</p>
    /// <p>Default: <code>CUSTOMER</code></p>
    pub log_scope: ::std::option::Option<crate::types::LogScope>,
}
impl ListLoggingConfigurationsInput {
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn scope(&self) -> ::std::option::Option<&crate::types::Scope> {
        self.scope.as_ref()
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>The maximum number of objects that you want WAF to return for this request. If more objects are available, in the response, WAF provides a <code>NextMarker</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>The owner of the logging configuration, which must be set to <code>CUSTOMER</code> for the configurations that you manage.</p>
    /// <p>The log scope <code>SECURITY_LAKE</code> indicates a configuration that is managed through Amazon Security Lake. You can use Security Lake to collect log and event data from various sources for normalization, analysis, and management. For information, see <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html">Collecting data from Amazon Web Services services</a> in the <i>Amazon Security Lake user guide</i>.</p>
    /// <p>Default: <code>CUSTOMER</code></p>
    pub fn log_scope(&self) -> ::std::option::Option<&crate::types::LogScope> {
        self.log_scope.as_ref()
    }
}
impl ListLoggingConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`ListLoggingConfigurationsInput`](crate::operation::list_logging_configurations::ListLoggingConfigurationsInput).
    pub fn builder() -> crate::operation::list_logging_configurations::builders::ListLoggingConfigurationsInputBuilder {
        crate::operation::list_logging_configurations::builders::ListLoggingConfigurationsInputBuilder::default()
    }
}

/// A builder for [`ListLoggingConfigurationsInput`](crate::operation::list_logging_configurations::ListLoggingConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLoggingConfigurationsInputBuilder {
    pub(crate) scope: ::std::option::Option<crate::types::Scope>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) log_scope: ::std::option::Option<crate::types::LogScope>,
}
impl ListLoggingConfigurationsInputBuilder {
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    /// This field is required.
    pub fn scope(mut self, input: crate::types::Scope) -> Self {
        self.scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn set_scope(mut self, input: ::std::option::Option<crate::types::Scope>) -> Self {
        self.scope = input;
        self
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn get_scope(&self) -> &::std::option::Option<crate::types::Scope> {
        &self.scope
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>When you request a list of objects with a <code>Limit</code> setting, if the number of objects that are still available for retrieval exceeds the limit, WAF returns a <code>NextMarker</code> value in the response. To retrieve the next batch of objects, provide the marker from the prior call in your next request.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// <p>The maximum number of objects that you want WAF to return for this request. If more objects are available, in the response, WAF provides a <code>NextMarker</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of objects that you want WAF to return for this request. If more objects are available, in the response, WAF provides a <code>NextMarker</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of objects that you want WAF to return for this request. If more objects are available, in the response, WAF provides a <code>NextMarker</code> value that you can use in a subsequent call to get the next batch of objects.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>The owner of the logging configuration, which must be set to <code>CUSTOMER</code> for the configurations that you manage.</p>
    /// <p>The log scope <code>SECURITY_LAKE</code> indicates a configuration that is managed through Amazon Security Lake. You can use Security Lake to collect log and event data from various sources for normalization, analysis, and management. For information, see <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html">Collecting data from Amazon Web Services services</a> in the <i>Amazon Security Lake user guide</i>.</p>
    /// <p>Default: <code>CUSTOMER</code></p>
    pub fn log_scope(mut self, input: crate::types::LogScope) -> Self {
        self.log_scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>The owner of the logging configuration, which must be set to <code>CUSTOMER</code> for the configurations that you manage.</p>
    /// <p>The log scope <code>SECURITY_LAKE</code> indicates a configuration that is managed through Amazon Security Lake. You can use Security Lake to collect log and event data from various sources for normalization, analysis, and management. For information, see <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html">Collecting data from Amazon Web Services services</a> in the <i>Amazon Security Lake user guide</i>.</p>
    /// <p>Default: <code>CUSTOMER</code></p>
    pub fn set_log_scope(mut self, input: ::std::option::Option<crate::types::LogScope>) -> Self {
        self.log_scope = input;
        self
    }
    /// <p>The owner of the logging configuration, which must be set to <code>CUSTOMER</code> for the configurations that you manage.</p>
    /// <p>The log scope <code>SECURITY_LAKE</code> indicates a configuration that is managed through Amazon Security Lake. You can use Security Lake to collect log and event data from various sources for normalization, analysis, and management. For information, see <a href="https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html">Collecting data from Amazon Web Services services</a> in the <i>Amazon Security Lake user guide</i>.</p>
    /// <p>Default: <code>CUSTOMER</code></p>
    pub fn get_log_scope(&self) -> &::std::option::Option<crate::types::LogScope> {
        &self.log_scope
    }
    /// Consumes the builder and constructs a [`ListLoggingConfigurationsInput`](crate::operation::list_logging_configurations::ListLoggingConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_logging_configurations::ListLoggingConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_logging_configurations::ListLoggingConfigurationsInput {
            scope: self.scope,
            next_marker: self.next_marker,
            limit: self.limit,
            log_scope: self.log_scope,
        })
    }
}
