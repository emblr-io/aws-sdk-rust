// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDatabaseInput {
    /// <p>The ID of the application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the component.</p>
    pub component_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the database.</p>
    pub database_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the database.</p>
    pub database_arn: ::std::option::Option<::std::string::String>,
}
impl GetDatabaseInput {
    /// <p>The ID of the application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The ID of the component.</p>
    pub fn component_id(&self) -> ::std::option::Option<&str> {
        self.component_id.as_deref()
    }
    /// <p>The ID of the database.</p>
    pub fn database_id(&self) -> ::std::option::Option<&str> {
        self.database_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the database.</p>
    pub fn database_arn(&self) -> ::std::option::Option<&str> {
        self.database_arn.as_deref()
    }
}
impl GetDatabaseInput {
    /// Creates a new builder-style object to manufacture [`GetDatabaseInput`](crate::operation::get_database::GetDatabaseInput).
    pub fn builder() -> crate::operation::get_database::builders::GetDatabaseInputBuilder {
        crate::operation::get_database::builders::GetDatabaseInputBuilder::default()
    }
}

/// A builder for [`GetDatabaseInput`](crate::operation::get_database::GetDatabaseInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDatabaseInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) component_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_arn: ::std::option::Option<::std::string::String>,
}
impl GetDatabaseInputBuilder {
    /// <p>The ID of the application.</p>
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The ID of the application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The ID of the component.</p>
    pub fn component_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the component.</p>
    pub fn set_component_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_id = input;
        self
    }
    /// <p>The ID of the component.</p>
    pub fn get_component_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_id
    }
    /// <p>The ID of the database.</p>
    pub fn database_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the database.</p>
    pub fn set_database_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_id = input;
        self
    }
    /// <p>The ID of the database.</p>
    pub fn get_database_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_id
    }
    /// <p>The Amazon Resource Name (ARN) of the database.</p>
    pub fn database_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the database.</p>
    pub fn set_database_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the database.</p>
    pub fn get_database_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_arn
    }
    /// Consumes the builder and constructs a [`GetDatabaseInput`](crate::operation::get_database::GetDatabaseInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_database::GetDatabaseInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_database::GetDatabaseInput {
            application_id: self.application_id,
            component_id: self.component_id,
            database_id: self.database_id,
            database_arn: self.database_arn,
        })
    }
}
