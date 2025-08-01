// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLambdaFunctionsOutput {
    /// <p>The Lambdafunction ARNs associated with the specified instance.</p>
    pub lambda_functions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLambdaFunctionsOutput {
    /// <p>The Lambdafunction ARNs associated with the specified instance.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.lambda_functions.is_none()`.
    pub fn lambda_functions(&self) -> &[::std::string::String] {
        self.lambda_functions.as_deref().unwrap_or_default()
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListLambdaFunctionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListLambdaFunctionsOutput {
    /// Creates a new builder-style object to manufacture [`ListLambdaFunctionsOutput`](crate::operation::list_lambda_functions::ListLambdaFunctionsOutput).
    pub fn builder() -> crate::operation::list_lambda_functions::builders::ListLambdaFunctionsOutputBuilder {
        crate::operation::list_lambda_functions::builders::ListLambdaFunctionsOutputBuilder::default()
    }
}

/// A builder for [`ListLambdaFunctionsOutput`](crate::operation::list_lambda_functions::ListLambdaFunctionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLambdaFunctionsOutputBuilder {
    pub(crate) lambda_functions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListLambdaFunctionsOutputBuilder {
    /// Appends an item to `lambda_functions`.
    ///
    /// To override the contents of this collection use [`set_lambda_functions`](Self::set_lambda_functions).
    ///
    /// <p>The Lambdafunction ARNs associated with the specified instance.</p>
    pub fn lambda_functions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.lambda_functions.unwrap_or_default();
        v.push(input.into());
        self.lambda_functions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Lambdafunction ARNs associated with the specified instance.</p>
    pub fn set_lambda_functions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.lambda_functions = input;
        self
    }
    /// <p>The Lambdafunction ARNs associated with the specified instance.</p>
    pub fn get_lambda_functions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.lambda_functions
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListLambdaFunctionsOutput`](crate::operation::list_lambda_functions::ListLambdaFunctionsOutput).
    pub fn build(self) -> crate::operation::list_lambda_functions::ListLambdaFunctionsOutput {
        crate::operation::list_lambda_functions::ListLambdaFunctionsOutput {
            lambda_functions: self.lambda_functions,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
