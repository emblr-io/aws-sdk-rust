// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a custom data identifier.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetCustomDataIdentifierSummary {
    /// <p>The Amazon Resource Name (ARN) of the custom data identifier.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the custom data identifier was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Specifies whether the custom data identifier was deleted. If you delete a custom data identifier, Amazon Macie doesn't delete it permanently. Instead, it soft deletes the identifier.</p>
    pub deleted: ::std::option::Option<bool>,
    /// <p>The custom description of the custom data identifier.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the custom data identifier.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The custom name of the custom data identifier.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl BatchGetCustomDataIdentifierSummary {
    /// <p>The Amazon Resource Name (ARN) of the custom data identifier.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the custom data identifier was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>Specifies whether the custom data identifier was deleted. If you delete a custom data identifier, Amazon Macie doesn't delete it permanently. Instead, it soft deletes the identifier.</p>
    pub fn deleted(&self) -> ::std::option::Option<bool> {
        self.deleted
    }
    /// <p>The custom description of the custom data identifier.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The unique identifier for the custom data identifier.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The custom name of the custom data identifier.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl BatchGetCustomDataIdentifierSummary {
    /// Creates a new builder-style object to manufacture [`BatchGetCustomDataIdentifierSummary`](crate::types::BatchGetCustomDataIdentifierSummary).
    pub fn builder() -> crate::types::builders::BatchGetCustomDataIdentifierSummaryBuilder {
        crate::types::builders::BatchGetCustomDataIdentifierSummaryBuilder::default()
    }
}

/// A builder for [`BatchGetCustomDataIdentifierSummary`](crate::types::BatchGetCustomDataIdentifierSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetCustomDataIdentifierSummaryBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) deleted: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl BatchGetCustomDataIdentifierSummaryBuilder {
    /// <p>The Amazon Resource Name (ARN) of the custom data identifier.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom data identifier.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom data identifier.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the custom data identifier was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the custom data identifier was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when the custom data identifier was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>Specifies whether the custom data identifier was deleted. If you delete a custom data identifier, Amazon Macie doesn't delete it permanently. Instead, it soft deletes the identifier.</p>
    pub fn deleted(mut self, input: bool) -> Self {
        self.deleted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the custom data identifier was deleted. If you delete a custom data identifier, Amazon Macie doesn't delete it permanently. Instead, it soft deletes the identifier.</p>
    pub fn set_deleted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.deleted = input;
        self
    }
    /// <p>Specifies whether the custom data identifier was deleted. If you delete a custom data identifier, Amazon Macie doesn't delete it permanently. Instead, it soft deletes the identifier.</p>
    pub fn get_deleted(&self) -> &::std::option::Option<bool> {
        &self.deleted
    }
    /// <p>The custom description of the custom data identifier.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom description of the custom data identifier.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The custom description of the custom data identifier.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The unique identifier for the custom data identifier.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the custom data identifier.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the custom data identifier.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The custom name of the custom data identifier.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The custom name of the custom data identifier.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The custom name of the custom data identifier.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`BatchGetCustomDataIdentifierSummary`](crate::types::BatchGetCustomDataIdentifierSummary).
    pub fn build(self) -> crate::types::BatchGetCustomDataIdentifierSummary {
        crate::types::BatchGetCustomDataIdentifierSummary {
            arn: self.arn,
            created_at: self.created_at,
            deleted: self.deleted,
            description: self.description,
            id: self.id,
            name: self.name,
        }
    }
}
