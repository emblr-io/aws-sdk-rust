// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct StartProtectedQueryInput {
    /// <p>The type of the protected query to be started.</p>
    pub r#type: ::std::option::Option<crate::types::ProtectedQueryType>,
    /// <p>A unique identifier for the membership to run this query against. Currently accepts a membership ID.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The protected SQL query parameters.</p>
    pub sql_parameters: ::std::option::Option<crate::types::ProtectedQuerySqlParameters>,
    /// <p>The details needed to write the query results.</p>
    pub result_configuration: ::std::option::Option<crate::types::ProtectedQueryResultConfiguration>,
    /// <p>The compute configuration for the protected query.</p>
    pub compute_configuration: ::std::option::Option<crate::types::ComputeConfiguration>,
}
impl StartProtectedQueryInput {
    /// <p>The type of the protected query to be started.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ProtectedQueryType> {
        self.r#type.as_ref()
    }
    /// <p>A unique identifier for the membership to run this query against. Currently accepts a membership ID.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
    /// <p>The protected SQL query parameters.</p>
    pub fn sql_parameters(&self) -> ::std::option::Option<&crate::types::ProtectedQuerySqlParameters> {
        self.sql_parameters.as_ref()
    }
    /// <p>The details needed to write the query results.</p>
    pub fn result_configuration(&self) -> ::std::option::Option<&crate::types::ProtectedQueryResultConfiguration> {
        self.result_configuration.as_ref()
    }
    /// <p>The compute configuration for the protected query.</p>
    pub fn compute_configuration(&self) -> ::std::option::Option<&crate::types::ComputeConfiguration> {
        self.compute_configuration.as_ref()
    }
}
impl ::std::fmt::Debug for StartProtectedQueryInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartProtectedQueryInput");
        formatter.field("r#type", &self.r#type);
        formatter.field("membership_identifier", &self.membership_identifier);
        formatter.field("sql_parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("result_configuration", &self.result_configuration);
        formatter.field("compute_configuration", &self.compute_configuration);
        formatter.finish()
    }
}
impl StartProtectedQueryInput {
    /// Creates a new builder-style object to manufacture [`StartProtectedQueryInput`](crate::operation::start_protected_query::StartProtectedQueryInput).
    pub fn builder() -> crate::operation::start_protected_query::builders::StartProtectedQueryInputBuilder {
        crate::operation::start_protected_query::builders::StartProtectedQueryInputBuilder::default()
    }
}

/// A builder for [`StartProtectedQueryInput`](crate::operation::start_protected_query::StartProtectedQueryInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct StartProtectedQueryInputBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ProtectedQueryType>,
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) sql_parameters: ::std::option::Option<crate::types::ProtectedQuerySqlParameters>,
    pub(crate) result_configuration: ::std::option::Option<crate::types::ProtectedQueryResultConfiguration>,
    pub(crate) compute_configuration: ::std::option::Option<crate::types::ComputeConfiguration>,
}
impl StartProtectedQueryInputBuilder {
    /// <p>The type of the protected query to be started.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ProtectedQueryType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the protected query to be started.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ProtectedQueryType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the protected query to be started.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ProtectedQueryType> {
        &self.r#type
    }
    /// <p>A unique identifier for the membership to run this query against. Currently accepts a membership ID.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the membership to run this query against. Currently accepts a membership ID.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>A unique identifier for the membership to run this query against. Currently accepts a membership ID.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
    }
    /// <p>The protected SQL query parameters.</p>
    /// This field is required.
    pub fn sql_parameters(mut self, input: crate::types::ProtectedQuerySqlParameters) -> Self {
        self.sql_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The protected SQL query parameters.</p>
    pub fn set_sql_parameters(mut self, input: ::std::option::Option<crate::types::ProtectedQuerySqlParameters>) -> Self {
        self.sql_parameters = input;
        self
    }
    /// <p>The protected SQL query parameters.</p>
    pub fn get_sql_parameters(&self) -> &::std::option::Option<crate::types::ProtectedQuerySqlParameters> {
        &self.sql_parameters
    }
    /// <p>The details needed to write the query results.</p>
    pub fn result_configuration(mut self, input: crate::types::ProtectedQueryResultConfiguration) -> Self {
        self.result_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details needed to write the query results.</p>
    pub fn set_result_configuration(mut self, input: ::std::option::Option<crate::types::ProtectedQueryResultConfiguration>) -> Self {
        self.result_configuration = input;
        self
    }
    /// <p>The details needed to write the query results.</p>
    pub fn get_result_configuration(&self) -> &::std::option::Option<crate::types::ProtectedQueryResultConfiguration> {
        &self.result_configuration
    }
    /// <p>The compute configuration for the protected query.</p>
    pub fn compute_configuration(mut self, input: crate::types::ComputeConfiguration) -> Self {
        self.compute_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compute configuration for the protected query.</p>
    pub fn set_compute_configuration(mut self, input: ::std::option::Option<crate::types::ComputeConfiguration>) -> Self {
        self.compute_configuration = input;
        self
    }
    /// <p>The compute configuration for the protected query.</p>
    pub fn get_compute_configuration(&self) -> &::std::option::Option<crate::types::ComputeConfiguration> {
        &self.compute_configuration
    }
    /// Consumes the builder and constructs a [`StartProtectedQueryInput`](crate::operation::start_protected_query::StartProtectedQueryInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_protected_query::StartProtectedQueryInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_protected_query::StartProtectedQueryInput {
            r#type: self.r#type,
            membership_identifier: self.membership_identifier,
            sql_parameters: self.sql_parameters,
            result_configuration: self.result_configuration,
            compute_configuration: self.compute_configuration,
        })
    }
}
impl ::std::fmt::Debug for StartProtectedQueryInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("StartProtectedQueryInputBuilder");
        formatter.field("r#type", &self.r#type);
        formatter.field("membership_identifier", &self.membership_identifier);
        formatter.field("sql_parameters", &"*** Sensitive Data Redacted ***");
        formatter.field("result_configuration", &self.result_configuration);
        formatter.field("compute_configuration", &self.compute_configuration);
        formatter.finish()
    }
}
