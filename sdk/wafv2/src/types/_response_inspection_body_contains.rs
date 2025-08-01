// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures inspection of the response body. WAF can inspect the first 65,536 bytes (64 KB) of the response body. This is part of the <code>ResponseInspection</code> configuration for <code>AWSManagedRulesATPRuleSet</code> and <code>AWSManagedRulesACFPRuleSet</code>.</p><note>
/// <p>Response inspection is available only in web ACLs that protect Amazon CloudFront distributions.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResponseInspectionBodyContains {
    /// <p>Strings in the body of the response that indicate a successful login or account creation attempt. To be counted as a success, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON examples: <code>"SuccessStrings": \[ "Login successful" \]</code> and <code>"SuccessStrings": \[ "Account creation successful", "Welcome to our site!" \]</code></p>
    pub success_strings: ::std::vec::Vec<::std::string::String>,
    /// <p>Strings in the body of the response that indicate a failed login or account creation attempt. To be counted as a failure, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON example: <code>"FailureStrings": \[ "Request failed" \]</code></p>
    pub failure_strings: ::std::vec::Vec<::std::string::String>,
}
impl ResponseInspectionBodyContains {
    /// <p>Strings in the body of the response that indicate a successful login or account creation attempt. To be counted as a success, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON examples: <code>"SuccessStrings": \[ "Login successful" \]</code> and <code>"SuccessStrings": \[ "Account creation successful", "Welcome to our site!" \]</code></p>
    pub fn success_strings(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.success_strings.deref()
    }
    /// <p>Strings in the body of the response that indicate a failed login or account creation attempt. To be counted as a failure, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON example: <code>"FailureStrings": \[ "Request failed" \]</code></p>
    pub fn failure_strings(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.failure_strings.deref()
    }
}
impl ResponseInspectionBodyContains {
    /// Creates a new builder-style object to manufacture [`ResponseInspectionBodyContains`](crate::types::ResponseInspectionBodyContains).
    pub fn builder() -> crate::types::builders::ResponseInspectionBodyContainsBuilder {
        crate::types::builders::ResponseInspectionBodyContainsBuilder::default()
    }
}

/// A builder for [`ResponseInspectionBodyContains`](crate::types::ResponseInspectionBodyContains).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResponseInspectionBodyContainsBuilder {
    pub(crate) success_strings: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) failure_strings: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ResponseInspectionBodyContainsBuilder {
    /// Appends an item to `success_strings`.
    ///
    /// To override the contents of this collection use [`set_success_strings`](Self::set_success_strings).
    ///
    /// <p>Strings in the body of the response that indicate a successful login or account creation attempt. To be counted as a success, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON examples: <code>"SuccessStrings": \[ "Login successful" \]</code> and <code>"SuccessStrings": \[ "Account creation successful", "Welcome to our site!" \]</code></p>
    pub fn success_strings(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.success_strings.unwrap_or_default();
        v.push(input.into());
        self.success_strings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Strings in the body of the response that indicate a successful login or account creation attempt. To be counted as a success, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON examples: <code>"SuccessStrings": \[ "Login successful" \]</code> and <code>"SuccessStrings": \[ "Account creation successful", "Welcome to our site!" \]</code></p>
    pub fn set_success_strings(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.success_strings = input;
        self
    }
    /// <p>Strings in the body of the response that indicate a successful login or account creation attempt. To be counted as a success, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON examples: <code>"SuccessStrings": \[ "Login successful" \]</code> and <code>"SuccessStrings": \[ "Account creation successful", "Welcome to our site!" \]</code></p>
    pub fn get_success_strings(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.success_strings
    }
    /// Appends an item to `failure_strings`.
    ///
    /// To override the contents of this collection use [`set_failure_strings`](Self::set_failure_strings).
    ///
    /// <p>Strings in the body of the response that indicate a failed login or account creation attempt. To be counted as a failure, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON example: <code>"FailureStrings": \[ "Request failed" \]</code></p>
    pub fn failure_strings(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.failure_strings.unwrap_or_default();
        v.push(input.into());
        self.failure_strings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Strings in the body of the response that indicate a failed login or account creation attempt. To be counted as a failure, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON example: <code>"FailureStrings": \[ "Request failed" \]</code></p>
    pub fn set_failure_strings(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.failure_strings = input;
        self
    }
    /// <p>Strings in the body of the response that indicate a failed login or account creation attempt. To be counted as a failure, the string can be anywhere in the body and must be an exact match, including case. Each string must be unique among the success and failure strings.</p>
    /// <p>JSON example: <code>"FailureStrings": \[ "Request failed" \]</code></p>
    pub fn get_failure_strings(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.failure_strings
    }
    /// Consumes the builder and constructs a [`ResponseInspectionBodyContains`](crate::types::ResponseInspectionBodyContains).
    /// This method will fail if any of the following fields are not set:
    /// - [`success_strings`](crate::types::builders::ResponseInspectionBodyContainsBuilder::success_strings)
    /// - [`failure_strings`](crate::types::builders::ResponseInspectionBodyContainsBuilder::failure_strings)
    pub fn build(self) -> ::std::result::Result<crate::types::ResponseInspectionBodyContains, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResponseInspectionBodyContains {
            success_strings: self.success_strings.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "success_strings",
                    "success_strings was not specified but it is required when building ResponseInspectionBodyContains",
                )
            })?,
            failure_strings: self.failure_strings.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "failure_strings",
                    "failure_strings was not specified but it is required when building ResponseInspectionBodyContains",
                )
            })?,
        })
    }
}
