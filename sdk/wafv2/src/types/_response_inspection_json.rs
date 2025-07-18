// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configures inspection of the response JSON. WAF can inspect the first 65,536 bytes (64 KB) of the response JSON. This is part of the <code>ResponseInspection</code> configuration for <code>AWSManagedRulesATPRuleSet</code> and <code>AWSManagedRulesACFPRuleSet</code>.</p><note>
/// <p>Response inspection is available only in web ACLs that protect Amazon CloudFront distributions.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResponseInspectionJson {
    /// <p>The identifier for the value to match against in the JSON. The identifier must be an exact match, including case.</p>
    /// <p>JSON examples: <code>"Identifier": \[ "/login/success" \]</code> and <code>"Identifier": \[ "/sign-up/success" \]</code></p>
    pub identifier: ::std::string::String,
    /// <p>Values for the specified identifier in the response JSON that indicate a successful login or account creation attempt. To be counted as a success, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"SuccessValues": \[ "True", "Succeeded" \]</code></p>
    pub success_values: ::std::vec::Vec<::std::string::String>,
    /// <p>Values for the specified identifier in the response JSON that indicate a failed login or account creation attempt. To be counted as a failure, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"FailureValues": \[ "False", "Failed" \]</code></p>
    pub failure_values: ::std::vec::Vec<::std::string::String>,
}
impl ResponseInspectionJson {
    /// <p>The identifier for the value to match against in the JSON. The identifier must be an exact match, including case.</p>
    /// <p>JSON examples: <code>"Identifier": \[ "/login/success" \]</code> and <code>"Identifier": \[ "/sign-up/success" \]</code></p>
    pub fn identifier(&self) -> &str {
        use std::ops::Deref;
        self.identifier.deref()
    }
    /// <p>Values for the specified identifier in the response JSON that indicate a successful login or account creation attempt. To be counted as a success, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"SuccessValues": \[ "True", "Succeeded" \]</code></p>
    pub fn success_values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.success_values.deref()
    }
    /// <p>Values for the specified identifier in the response JSON that indicate a failed login or account creation attempt. To be counted as a failure, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"FailureValues": \[ "False", "Failed" \]</code></p>
    pub fn failure_values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.failure_values.deref()
    }
}
impl ResponseInspectionJson {
    /// Creates a new builder-style object to manufacture [`ResponseInspectionJson`](crate::types::ResponseInspectionJson).
    pub fn builder() -> crate::types::builders::ResponseInspectionJsonBuilder {
        crate::types::builders::ResponseInspectionJsonBuilder::default()
    }
}

/// A builder for [`ResponseInspectionJson`](crate::types::ResponseInspectionJson).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResponseInspectionJsonBuilder {
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) success_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) failure_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ResponseInspectionJsonBuilder {
    /// <p>The identifier for the value to match against in the JSON. The identifier must be an exact match, including case.</p>
    /// <p>JSON examples: <code>"Identifier": \[ "/login/success" \]</code> and <code>"Identifier": \[ "/sign-up/success" \]</code></p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the value to match against in the JSON. The identifier must be an exact match, including case.</p>
    /// <p>JSON examples: <code>"Identifier": \[ "/login/success" \]</code> and <code>"Identifier": \[ "/sign-up/success" \]</code></p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The identifier for the value to match against in the JSON. The identifier must be an exact match, including case.</p>
    /// <p>JSON examples: <code>"Identifier": \[ "/login/success" \]</code> and <code>"Identifier": \[ "/sign-up/success" \]</code></p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// Appends an item to `success_values`.
    ///
    /// To override the contents of this collection use [`set_success_values`](Self::set_success_values).
    ///
    /// <p>Values for the specified identifier in the response JSON that indicate a successful login or account creation attempt. To be counted as a success, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"SuccessValues": \[ "True", "Succeeded" \]</code></p>
    pub fn success_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.success_values.unwrap_or_default();
        v.push(input.into());
        self.success_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Values for the specified identifier in the response JSON that indicate a successful login or account creation attempt. To be counted as a success, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"SuccessValues": \[ "True", "Succeeded" \]</code></p>
    pub fn set_success_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.success_values = input;
        self
    }
    /// <p>Values for the specified identifier in the response JSON that indicate a successful login or account creation attempt. To be counted as a success, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"SuccessValues": \[ "True", "Succeeded" \]</code></p>
    pub fn get_success_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.success_values
    }
    /// Appends an item to `failure_values`.
    ///
    /// To override the contents of this collection use [`set_failure_values`](Self::set_failure_values).
    ///
    /// <p>Values for the specified identifier in the response JSON that indicate a failed login or account creation attempt. To be counted as a failure, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"FailureValues": \[ "False", "Failed" \]</code></p>
    pub fn failure_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.failure_values.unwrap_or_default();
        v.push(input.into());
        self.failure_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>Values for the specified identifier in the response JSON that indicate a failed login or account creation attempt. To be counted as a failure, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"FailureValues": \[ "False", "Failed" \]</code></p>
    pub fn set_failure_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.failure_values = input;
        self
    }
    /// <p>Values for the specified identifier in the response JSON that indicate a failed login or account creation attempt. To be counted as a failure, the value must be an exact match, including case. Each value must be unique among the success and failure values.</p>
    /// <p>JSON example: <code>"FailureValues": \[ "False", "Failed" \]</code></p>
    pub fn get_failure_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.failure_values
    }
    /// Consumes the builder and constructs a [`ResponseInspectionJson`](crate::types::ResponseInspectionJson).
    /// This method will fail if any of the following fields are not set:
    /// - [`identifier`](crate::types::builders::ResponseInspectionJsonBuilder::identifier)
    /// - [`success_values`](crate::types::builders::ResponseInspectionJsonBuilder::success_values)
    /// - [`failure_values`](crate::types::builders::ResponseInspectionJsonBuilder::failure_values)
    pub fn build(self) -> ::std::result::Result<crate::types::ResponseInspectionJson, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResponseInspectionJson {
            identifier: self.identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identifier",
                    "identifier was not specified but it is required when building ResponseInspectionJson",
                )
            })?,
            success_values: self.success_values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "success_values",
                    "success_values was not specified but it is required when building ResponseInspectionJson",
                )
            })?,
            failure_values: self.failure_values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "failure_values",
                    "failure_values was not specified but it is required when building ResponseInspectionJson",
                )
            })?,
        })
    }
}
