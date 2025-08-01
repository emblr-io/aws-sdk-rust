// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeRegistrationFieldValuesOutput {
    /// <p>The Amazon Resource Name (ARN) for the registration.</p>
    pub registration_arn: ::std::string::String,
    /// <p>The unique identifier for the registration.</p>
    pub registration_id: ::std::string::String,
    /// <p>The current version of the registration.</p>
    pub version_number: i64,
    /// <p>An array of RegistrationFieldValues objects that contain the values for the requested registration.</p>
    pub registration_field_values: ::std::vec::Vec<crate::types::RegistrationFieldValueInformation>,
    /// <p>The token to be used for the next set of paginated results. You don't need to supply a value for this field in the initial request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeRegistrationFieldValuesOutput {
    /// <p>The Amazon Resource Name (ARN) for the registration.</p>
    pub fn registration_arn(&self) -> &str {
        use std::ops::Deref;
        self.registration_arn.deref()
    }
    /// <p>The unique identifier for the registration.</p>
    pub fn registration_id(&self) -> &str {
        use std::ops::Deref;
        self.registration_id.deref()
    }
    /// <p>The current version of the registration.</p>
    pub fn version_number(&self) -> i64 {
        self.version_number
    }
    /// <p>An array of RegistrationFieldValues objects that contain the values for the requested registration.</p>
    pub fn registration_field_values(&self) -> &[crate::types::RegistrationFieldValueInformation] {
        use std::ops::Deref;
        self.registration_field_values.deref()
    }
    /// <p>The token to be used for the next set of paginated results. You don't need to supply a value for this field in the initial request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeRegistrationFieldValuesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeRegistrationFieldValuesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeRegistrationFieldValuesOutput`](crate::operation::describe_registration_field_values::DescribeRegistrationFieldValuesOutput).
    pub fn builder() -> crate::operation::describe_registration_field_values::builders::DescribeRegistrationFieldValuesOutputBuilder {
        crate::operation::describe_registration_field_values::builders::DescribeRegistrationFieldValuesOutputBuilder::default()
    }
}

/// A builder for [`DescribeRegistrationFieldValuesOutput`](crate::operation::describe_registration_field_values::DescribeRegistrationFieldValuesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeRegistrationFieldValuesOutputBuilder {
    pub(crate) registration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) registration_id: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i64>,
    pub(crate) registration_field_values: ::std::option::Option<::std::vec::Vec<crate::types::RegistrationFieldValueInformation>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeRegistrationFieldValuesOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) for the registration.</p>
    /// This field is required.
    pub fn registration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the registration.</p>
    pub fn set_registration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the registration.</p>
    pub fn get_registration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.registration_arn
    }
    /// <p>The unique identifier for the registration.</p>
    /// This field is required.
    pub fn registration_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registration_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the registration.</p>
    pub fn set_registration_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registration_id = input;
        self
    }
    /// <p>The unique identifier for the registration.</p>
    pub fn get_registration_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registration_id
    }
    /// <p>The current version of the registration.</p>
    /// This field is required.
    pub fn version_number(mut self, input: i64) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current version of the registration.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The current version of the registration.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i64> {
        &self.version_number
    }
    /// Appends an item to `registration_field_values`.
    ///
    /// To override the contents of this collection use [`set_registration_field_values`](Self::set_registration_field_values).
    ///
    /// <p>An array of RegistrationFieldValues objects that contain the values for the requested registration.</p>
    pub fn registration_field_values(mut self, input: crate::types::RegistrationFieldValueInformation) -> Self {
        let mut v = self.registration_field_values.unwrap_or_default();
        v.push(input);
        self.registration_field_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of RegistrationFieldValues objects that contain the values for the requested registration.</p>
    pub fn set_registration_field_values(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::RegistrationFieldValueInformation>>,
    ) -> Self {
        self.registration_field_values = input;
        self
    }
    /// <p>An array of RegistrationFieldValues objects that contain the values for the requested registration.</p>
    pub fn get_registration_field_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RegistrationFieldValueInformation>> {
        &self.registration_field_values
    }
    /// <p>The token to be used for the next set of paginated results. You don't need to supply a value for this field in the initial request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to be used for the next set of paginated results. You don't need to supply a value for this field in the initial request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to be used for the next set of paginated results. You don't need to supply a value for this field in the initial request.</p>
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
    /// Consumes the builder and constructs a [`DescribeRegistrationFieldValuesOutput`](crate::operation::describe_registration_field_values::DescribeRegistrationFieldValuesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`registration_arn`](crate::operation::describe_registration_field_values::builders::DescribeRegistrationFieldValuesOutputBuilder::registration_arn)
    /// - [`registration_id`](crate::operation::describe_registration_field_values::builders::DescribeRegistrationFieldValuesOutputBuilder::registration_id)
    /// - [`version_number`](crate::operation::describe_registration_field_values::builders::DescribeRegistrationFieldValuesOutputBuilder::version_number)
    /// - [`registration_field_values`](crate::operation::describe_registration_field_values::builders::DescribeRegistrationFieldValuesOutputBuilder::registration_field_values)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_registration_field_values::DescribeRegistrationFieldValuesOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_registration_field_values::DescribeRegistrationFieldValuesOutput {
                registration_arn: self.registration_arn.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "registration_arn",
                        "registration_arn was not specified but it is required when building DescribeRegistrationFieldValuesOutput",
                    )
                })?,
                registration_id: self.registration_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "registration_id",
                        "registration_id was not specified but it is required when building DescribeRegistrationFieldValuesOutput",
                    )
                })?,
                version_number: self.version_number.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "version_number",
                        "version_number was not specified but it is required when building DescribeRegistrationFieldValuesOutput",
                    )
                })?,
                registration_field_values: self.registration_field_values.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "registration_field_values",
                        "registration_field_values was not specified but it is required when building DescribeRegistrationFieldValuesOutput",
                    )
                })?,
                next_token: self.next_token,
                _request_id: self._request_id,
            },
        )
    }
}
