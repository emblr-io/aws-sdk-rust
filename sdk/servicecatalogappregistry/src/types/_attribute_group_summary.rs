// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summary of a Amazon Web Services Service Catalog AppRegistry attribute group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttributeGroupSummary {
    /// <p>The globally unique attribute group identifier of the attribute group.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon resource name (ARN) that specifies the attribute group across services.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the attribute group.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the attribute group that the user provides.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was last updated. This time is the same as the creationTime for a newly created attribute group.</p>
    pub last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The service principal that created the attribute group.</p>
    pub created_by: ::std::option::Option<::std::string::String>,
}
impl AttributeGroupSummary {
    /// <p>The globally unique attribute group identifier of the attribute group.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The Amazon resource name (ARN) that specifies the attribute group across services.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the attribute group.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the attribute group that the user provides.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was last updated. This time is the same as the creationTime for a newly created attribute group.</p>
    pub fn last_update_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_update_time.as_ref()
    }
    /// <p>The service principal that created the attribute group.</p>
    pub fn created_by(&self) -> ::std::option::Option<&str> {
        self.created_by.as_deref()
    }
}
impl AttributeGroupSummary {
    /// Creates a new builder-style object to manufacture [`AttributeGroupSummary`](crate::types::AttributeGroupSummary).
    pub fn builder() -> crate::types::builders::AttributeGroupSummaryBuilder {
        crate::types::builders::AttributeGroupSummaryBuilder::default()
    }
}

/// A builder for [`AttributeGroupSummary`](crate::types::AttributeGroupSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttributeGroupSummaryBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
}
impl AttributeGroupSummaryBuilder {
    /// <p>The globally unique attribute group identifier of the attribute group.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique attribute group identifier of the attribute group.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The globally unique attribute group identifier of the attribute group.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The Amazon resource name (ARN) that specifies the attribute group across services.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon resource name (ARN) that specifies the attribute group across services.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon resource name (ARN) that specifies the attribute group across services.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the attribute group.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the attribute group.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the attribute group.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the attribute group that the user provides.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the attribute group that the user provides.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the attribute group that the user provides.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was last updated. This time is the same as the creationTime for a newly created attribute group.</p>
    pub fn last_update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was last updated. This time is the same as the creationTime for a newly created attribute group.</p>
    pub fn set_last_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_time = input;
        self
    }
    /// <p>The ISO-8601 formatted timestamp of the moment the attribute group was last updated. This time is the same as the creationTime for a newly created attribute group.</p>
    pub fn get_last_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_time
    }
    /// <p>The service principal that created the attribute group.</p>
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The service principal that created the attribute group.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The service principal that created the attribute group.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// Consumes the builder and constructs a [`AttributeGroupSummary`](crate::types::AttributeGroupSummary).
    pub fn build(self) -> crate::types::AttributeGroupSummary {
        crate::types::AttributeGroupSummary {
            id: self.id,
            arn: self.arn,
            name: self.name,
            description: self.description,
            creation_time: self.creation_time,
            last_update_time: self.last_update_time,
            created_by: self.created_by,
        }
    }
}
