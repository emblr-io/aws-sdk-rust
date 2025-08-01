// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SchemaVersionSummary {
    /// <p>The ARN of the schema version.</p>
    pub schema_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the schema.</p>
    pub schema_name: ::std::option::Option<::std::string::String>,
    /// <p>The version number of the schema.</p>
    pub schema_version: ::std::option::Option<::std::string::String>,
    /// <p>The type of schema.</p>
    pub r#type: ::std::option::Option<crate::types::Type>,
}
impl SchemaVersionSummary {
    /// <p>The ARN of the schema version.</p>
    pub fn schema_arn(&self) -> ::std::option::Option<&str> {
        self.schema_arn.as_deref()
    }
    /// <p>The name of the schema.</p>
    pub fn schema_name(&self) -> ::std::option::Option<&str> {
        self.schema_name.as_deref()
    }
    /// <p>The version number of the schema.</p>
    pub fn schema_version(&self) -> ::std::option::Option<&str> {
        self.schema_version.as_deref()
    }
    /// <p>The type of schema.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::Type> {
        self.r#type.as_ref()
    }
}
impl SchemaVersionSummary {
    /// Creates a new builder-style object to manufacture [`SchemaVersionSummary`](crate::types::SchemaVersionSummary).
    pub fn builder() -> crate::types::builders::SchemaVersionSummaryBuilder {
        crate::types::builders::SchemaVersionSummaryBuilder::default()
    }
}

/// A builder for [`SchemaVersionSummary`](crate::types::SchemaVersionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SchemaVersionSummaryBuilder {
    pub(crate) schema_arn: ::std::option::Option<::std::string::String>,
    pub(crate) schema_name: ::std::option::Option<::std::string::String>,
    pub(crate) schema_version: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::Type>,
}
impl SchemaVersionSummaryBuilder {
    /// <p>The ARN of the schema version.</p>
    pub fn schema_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the schema version.</p>
    pub fn set_schema_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_arn = input;
        self
    }
    /// <p>The ARN of the schema version.</p>
    pub fn get_schema_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_arn
    }
    /// <p>The name of the schema.</p>
    pub fn schema_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schema.</p>
    pub fn set_schema_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_name = input;
        self
    }
    /// <p>The name of the schema.</p>
    pub fn get_schema_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_name
    }
    /// <p>The version number of the schema.</p>
    pub fn schema_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version number of the schema.</p>
    pub fn set_schema_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_version = input;
        self
    }
    /// <p>The version number of the schema.</p>
    pub fn get_schema_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_version
    }
    /// <p>The type of schema.</p>
    pub fn r#type(mut self, input: crate::types::Type) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of schema.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::Type>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of schema.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::Type> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`SchemaVersionSummary`](crate::types::SchemaVersionSummary).
    pub fn build(self) -> crate::types::SchemaVersionSummary {
        crate::types::SchemaVersionSummary {
            schema_arn: self.schema_arn,
            schema_name: self.schema_name,
            schema_version: self.schema_version,
            r#type: self.r#type,
        }
    }
}
