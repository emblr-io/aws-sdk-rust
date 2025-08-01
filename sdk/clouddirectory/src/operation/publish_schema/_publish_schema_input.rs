// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PublishSchemaInput {
    /// <p>The Amazon Resource Name (ARN) that is associated with the development schema. For more information, see <code>arns</code>.</p>
    pub development_schema_arn: ::std::option::Option<::std::string::String>,
    /// <p>The major version under which the schema will be published. Schemas have both a major and minor version associated with them.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The minor version under which the schema will be published. This parameter is recommended. Schemas have both a major and minor version associated with them.</p>
    pub minor_version: ::std::option::Option<::std::string::String>,
    /// <p>The new name under which the schema will be published. If this is not provided, the development schema is considered.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl PublishSchemaInput {
    /// <p>The Amazon Resource Name (ARN) that is associated with the development schema. For more information, see <code>arns</code>.</p>
    pub fn development_schema_arn(&self) -> ::std::option::Option<&str> {
        self.development_schema_arn.as_deref()
    }
    /// <p>The major version under which the schema will be published. Schemas have both a major and minor version associated with them.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The minor version under which the schema will be published. This parameter is recommended. Schemas have both a major and minor version associated with them.</p>
    pub fn minor_version(&self) -> ::std::option::Option<&str> {
        self.minor_version.as_deref()
    }
    /// <p>The new name under which the schema will be published. If this is not provided, the development schema is considered.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl PublishSchemaInput {
    /// Creates a new builder-style object to manufacture [`PublishSchemaInput`](crate::operation::publish_schema::PublishSchemaInput).
    pub fn builder() -> crate::operation::publish_schema::builders::PublishSchemaInputBuilder {
        crate::operation::publish_schema::builders::PublishSchemaInputBuilder::default()
    }
}

/// A builder for [`PublishSchemaInput`](crate::operation::publish_schema::PublishSchemaInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PublishSchemaInputBuilder {
    pub(crate) development_schema_arn: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) minor_version: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl PublishSchemaInputBuilder {
    /// <p>The Amazon Resource Name (ARN) that is associated with the development schema. For more information, see <code>arns</code>.</p>
    /// This field is required.
    pub fn development_schema_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.development_schema_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the development schema. For more information, see <code>arns</code>.</p>
    pub fn set_development_schema_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.development_schema_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the development schema. For more information, see <code>arns</code>.</p>
    pub fn get_development_schema_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.development_schema_arn
    }
    /// <p>The major version under which the schema will be published. Schemas have both a major and minor version associated with them.</p>
    /// This field is required.
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The major version under which the schema will be published. Schemas have both a major and minor version associated with them.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The major version under which the schema will be published. Schemas have both a major and minor version associated with them.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The minor version under which the schema will be published. This parameter is recommended. Schemas have both a major and minor version associated with them.</p>
    pub fn minor_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.minor_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The minor version under which the schema will be published. This parameter is recommended. Schemas have both a major and minor version associated with them.</p>
    pub fn set_minor_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.minor_version = input;
        self
    }
    /// <p>The minor version under which the schema will be published. This parameter is recommended. Schemas have both a major and minor version associated with them.</p>
    pub fn get_minor_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.minor_version
    }
    /// <p>The new name under which the schema will be published. If this is not provided, the development schema is considered.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new name under which the schema will be published. If this is not provided, the development schema is considered.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The new name under which the schema will be published. If this is not provided, the development schema is considered.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`PublishSchemaInput`](crate::operation::publish_schema::PublishSchemaInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::publish_schema::PublishSchemaInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::publish_schema::PublishSchemaInput {
            development_schema_arn: self.development_schema_arn,
            version: self.version,
            minor_version: self.minor_version,
            name: self.name,
        })
    }
}
