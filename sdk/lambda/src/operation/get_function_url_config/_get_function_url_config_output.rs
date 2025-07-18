// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFunctionUrlConfigOutput {
    /// <p>The HTTP URL endpoint for your function.</p>
    pub function_url: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of your function.</p>
    pub function_arn: ::std::string::String,
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub auth_type: crate::types::FunctionUrlAuthType,
    /// <p>The <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS">cross-origin resource sharing (CORS)</a> settings for your function URL.</p>
    pub cors: ::std::option::Option<crate::types::Cors>,
    /// <p>When the function URL was created, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub creation_time: ::std::string::String,
    /// <p>When the function URL configuration was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub last_modified_time: ::std::string::String,
    /// <p>Use one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>BUFFERED</code> – This is the default option. Lambda invokes your function using the <code>Invoke</code> API operation. Invocation results are available when the payload is complete. The maximum payload size is 6 MB.</p></li>
    /// <li>
    /// <p><code>RESPONSE_STREAM</code> – Your function streams payload results as they become available. Lambda invokes your function using the <code>InvokeWithResponseStream</code> API operation. The maximum response payload size is 20 MB, however, you can <a href="https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html">request a quota increase</a>.</p></li>
    /// </ul>
    pub invoke_mode: ::std::option::Option<crate::types::InvokeMode>,
    _request_id: Option<String>,
}
impl GetFunctionUrlConfigOutput {
    /// <p>The HTTP URL endpoint for your function.</p>
    pub fn function_url(&self) -> &str {
        use std::ops::Deref;
        self.function_url.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of your function.</p>
    pub fn function_arn(&self) -> &str {
        use std::ops::Deref;
        self.function_arn.deref()
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn auth_type(&self) -> &crate::types::FunctionUrlAuthType {
        &self.auth_type
    }
    /// <p>The <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS">cross-origin resource sharing (CORS)</a> settings for your function URL.</p>
    pub fn cors(&self) -> ::std::option::Option<&crate::types::Cors> {
        self.cors.as_ref()
    }
    /// <p>When the function URL was created, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn creation_time(&self) -> &str {
        use std::ops::Deref;
        self.creation_time.deref()
    }
    /// <p>When the function URL configuration was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn last_modified_time(&self) -> &str {
        use std::ops::Deref;
        self.last_modified_time.deref()
    }
    /// <p>Use one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>BUFFERED</code> – This is the default option. Lambda invokes your function using the <code>Invoke</code> API operation. Invocation results are available when the payload is complete. The maximum payload size is 6 MB.</p></li>
    /// <li>
    /// <p><code>RESPONSE_STREAM</code> – Your function streams payload results as they become available. Lambda invokes your function using the <code>InvokeWithResponseStream</code> API operation. The maximum response payload size is 20 MB, however, you can <a href="https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html">request a quota increase</a>.</p></li>
    /// </ul>
    pub fn invoke_mode(&self) -> ::std::option::Option<&crate::types::InvokeMode> {
        self.invoke_mode.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetFunctionUrlConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFunctionUrlConfigOutput {
    /// Creates a new builder-style object to manufacture [`GetFunctionUrlConfigOutput`](crate::operation::get_function_url_config::GetFunctionUrlConfigOutput).
    pub fn builder() -> crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder {
        crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder::default()
    }
}

/// A builder for [`GetFunctionUrlConfigOutput`](crate::operation::get_function_url_config::GetFunctionUrlConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFunctionUrlConfigOutputBuilder {
    pub(crate) function_url: ::std::option::Option<::std::string::String>,
    pub(crate) function_arn: ::std::option::Option<::std::string::String>,
    pub(crate) auth_type: ::std::option::Option<crate::types::FunctionUrlAuthType>,
    pub(crate) cors: ::std::option::Option<crate::types::Cors>,
    pub(crate) creation_time: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_time: ::std::option::Option<::std::string::String>,
    pub(crate) invoke_mode: ::std::option::Option<crate::types::InvokeMode>,
    _request_id: Option<String>,
}
impl GetFunctionUrlConfigOutputBuilder {
    /// <p>The HTTP URL endpoint for your function.</p>
    /// This field is required.
    pub fn function_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP URL endpoint for your function.</p>
    pub fn set_function_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_url = input;
        self
    }
    /// <p>The HTTP URL endpoint for your function.</p>
    pub fn get_function_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_url
    }
    /// <p>The Amazon Resource Name (ARN) of your function.</p>
    /// This field is required.
    pub fn function_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.function_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of your function.</p>
    pub fn set_function_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.function_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of your function.</p>
    pub fn get_function_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.function_arn
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    /// This field is required.
    pub fn auth_type(mut self, input: crate::types::FunctionUrlAuthType) -> Self {
        self.auth_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn set_auth_type(mut self, input: ::std::option::Option<crate::types::FunctionUrlAuthType>) -> Self {
        self.auth_type = input;
        self
    }
    /// <p>The type of authentication that your function URL uses. Set to <code>AWS_IAM</code> if you want to restrict access to authenticated users only. Set to <code>NONE</code> if you want to bypass IAM authentication to create a public endpoint. For more information, see <a href="https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html">Security and auth model for Lambda function URLs</a>.</p>
    pub fn get_auth_type(&self) -> &::std::option::Option<crate::types::FunctionUrlAuthType> {
        &self.auth_type
    }
    /// <p>The <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS">cross-origin resource sharing (CORS)</a> settings for your function URL.</p>
    pub fn cors(mut self, input: crate::types::Cors) -> Self {
        self.cors = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS">cross-origin resource sharing (CORS)</a> settings for your function URL.</p>
    pub fn set_cors(mut self, input: ::std::option::Option<crate::types::Cors>) -> Self {
        self.cors = input;
        self
    }
    /// <p>The <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS">cross-origin resource sharing (CORS)</a> settings for your function URL.</p>
    pub fn get_cors(&self) -> &::std::option::Option<crate::types::Cors> {
        &self.cors
    }
    /// <p>When the function URL was created, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    /// This field is required.
    pub fn creation_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creation_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the function URL was created, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>When the function URL was created, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.creation_time
    }
    /// <p>When the function URL configuration was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When the function URL configuration was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>When the function URL configuration was last updated, in <a href="https://www.w3.org/TR/NOTE-datetime">ISO-8601 format</a> (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_time
    }
    /// <p>Use one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>BUFFERED</code> – This is the default option. Lambda invokes your function using the <code>Invoke</code> API operation. Invocation results are available when the payload is complete. The maximum payload size is 6 MB.</p></li>
    /// <li>
    /// <p><code>RESPONSE_STREAM</code> – Your function streams payload results as they become available. Lambda invokes your function using the <code>InvokeWithResponseStream</code> API operation. The maximum response payload size is 20 MB, however, you can <a href="https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html">request a quota increase</a>.</p></li>
    /// </ul>
    pub fn invoke_mode(mut self, input: crate::types::InvokeMode) -> Self {
        self.invoke_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>BUFFERED</code> – This is the default option. Lambda invokes your function using the <code>Invoke</code> API operation. Invocation results are available when the payload is complete. The maximum payload size is 6 MB.</p></li>
    /// <li>
    /// <p><code>RESPONSE_STREAM</code> – Your function streams payload results as they become available. Lambda invokes your function using the <code>InvokeWithResponseStream</code> API operation. The maximum response payload size is 20 MB, however, you can <a href="https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html">request a quota increase</a>.</p></li>
    /// </ul>
    pub fn set_invoke_mode(mut self, input: ::std::option::Option<crate::types::InvokeMode>) -> Self {
        self.invoke_mode = input;
        self
    }
    /// <p>Use one of the following options:</p>
    /// <ul>
    /// <li>
    /// <p><code>BUFFERED</code> – This is the default option. Lambda invokes your function using the <code>Invoke</code> API operation. Invocation results are available when the payload is complete. The maximum payload size is 6 MB.</p></li>
    /// <li>
    /// <p><code>RESPONSE_STREAM</code> – Your function streams payload results as they become available. Lambda invokes your function using the <code>InvokeWithResponseStream</code> API operation. The maximum response payload size is 20 MB, however, you can <a href="https://docs.aws.amazon.com/servicequotas/latest/userguide/request-quota-increase.html">request a quota increase</a>.</p></li>
    /// </ul>
    pub fn get_invoke_mode(&self) -> &::std::option::Option<crate::types::InvokeMode> {
        &self.invoke_mode
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFunctionUrlConfigOutput`](crate::operation::get_function_url_config::GetFunctionUrlConfigOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`function_url`](crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder::function_url)
    /// - [`function_arn`](crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder::function_arn)
    /// - [`auth_type`](crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder::auth_type)
    /// - [`creation_time`](crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder::creation_time)
    /// - [`last_modified_time`](crate::operation::get_function_url_config::builders::GetFunctionUrlConfigOutputBuilder::last_modified_time)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_function_url_config::GetFunctionUrlConfigOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_function_url_config::GetFunctionUrlConfigOutput {
            function_url: self.function_url.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "function_url",
                    "function_url was not specified but it is required when building GetFunctionUrlConfigOutput",
                )
            })?,
            function_arn: self.function_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "function_arn",
                    "function_arn was not specified but it is required when building GetFunctionUrlConfigOutput",
                )
            })?,
            auth_type: self.auth_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "auth_type",
                    "auth_type was not specified but it is required when building GetFunctionUrlConfigOutput",
                )
            })?,
            cors: self.cors,
            creation_time: self.creation_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "creation_time",
                    "creation_time was not specified but it is required when building GetFunctionUrlConfigOutput",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building GetFunctionUrlConfigOutput",
                )
            })?,
            invoke_mode: self.invoke_mode,
            _request_id: self._request_id,
        })
    }
}
