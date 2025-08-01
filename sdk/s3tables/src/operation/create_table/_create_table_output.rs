// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTableOutput {
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub table_arn: ::std::string::String,
    /// <p>The version token of the table.</p>
    pub version_token: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateTableOutput {
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn table_arn(&self) -> &str {
        use std::ops::Deref;
        self.table_arn.deref()
    }
    /// <p>The version token of the table.</p>
    pub fn version_token(&self) -> &str {
        use std::ops::Deref;
        self.version_token.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateTableOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateTableOutput {
    /// Creates a new builder-style object to manufacture [`CreateTableOutput`](crate::operation::create_table::CreateTableOutput).
    pub fn builder() -> crate::operation::create_table::builders::CreateTableOutputBuilder {
        crate::operation::create_table::builders::CreateTableOutputBuilder::default()
    }
}

/// A builder for [`CreateTableOutput`](crate::operation::create_table::CreateTableOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTableOutputBuilder {
    pub(crate) table_arn: ::std::option::Option<::std::string::String>,
    pub(crate) version_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTableOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    /// This field is required.
    pub fn table_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn set_table_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table.</p>
    pub fn get_table_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_arn
    }
    /// <p>The version token of the table.</p>
    /// This field is required.
    pub fn version_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version token of the table.</p>
    pub fn set_version_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_token = input;
        self
    }
    /// <p>The version token of the table.</p>
    pub fn get_version_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateTableOutput`](crate::operation::create_table::CreateTableOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`table_arn`](crate::operation::create_table::builders::CreateTableOutputBuilder::table_arn)
    /// - [`version_token`](crate::operation::create_table::builders::CreateTableOutputBuilder::version_token)
    pub fn build(self) -> ::std::result::Result<crate::operation::create_table::CreateTableOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_table::CreateTableOutput {
            table_arn: self.table_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "table_arn",
                    "table_arn was not specified but it is required when building CreateTableOutput",
                )
            })?,
            version_token: self.version_token.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "version_token",
                    "version_token was not specified but it is required when building CreateTableOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
