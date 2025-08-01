// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateSchemaInput {
    /// <p>The Amazon Resource Name (ARN) of the development schema. For more information, see <code>arns</code>.</p>
    pub schema_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the schema.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl UpdateSchemaInput {
    /// <p>The Amazon Resource Name (ARN) of the development schema. For more information, see <code>arns</code>.</p>
    pub fn schema_arn(&self) -> ::std::option::Option<&str> {
        self.schema_arn.as_deref()
    }
    /// <p>The name of the schema.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl UpdateSchemaInput {
    /// Creates a new builder-style object to manufacture [`UpdateSchemaInput`](crate::operation::update_schema::UpdateSchemaInput).
    pub fn builder() -> crate::operation::update_schema::builders::UpdateSchemaInputBuilder {
        crate::operation::update_schema::builders::UpdateSchemaInputBuilder::default()
    }
}

/// A builder for [`UpdateSchemaInput`](crate::operation::update_schema::UpdateSchemaInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateSchemaInputBuilder {
    pub(crate) schema_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl UpdateSchemaInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the development schema. For more information, see <code>arns</code>.</p>
    /// This field is required.
    pub fn schema_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the development schema. For more information, see <code>arns</code>.</p>
    pub fn set_schema_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the development schema. For more information, see <code>arns</code>.</p>
    pub fn get_schema_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_arn
    }
    /// <p>The name of the schema.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the schema.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the schema.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`UpdateSchemaInput`](crate::operation::update_schema::UpdateSchemaInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_schema::UpdateSchemaInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_schema::UpdateSchemaInput {
            schema_arn: self.schema_arn,
            name: self.name,
        })
    }
}
