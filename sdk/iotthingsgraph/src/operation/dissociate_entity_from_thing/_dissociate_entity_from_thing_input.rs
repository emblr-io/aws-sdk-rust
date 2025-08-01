// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DissociateEntityFromThingInput {
    /// <p>The name of the thing to disassociate.</p>
    pub thing_name: ::std::option::Option<::std::string::String>,
    /// <p>The entity type from which to disassociate the thing.</p>
    pub entity_type: ::std::option::Option<crate::types::EntityType>,
}
impl DissociateEntityFromThingInput {
    /// <p>The name of the thing to disassociate.</p>
    pub fn thing_name(&self) -> ::std::option::Option<&str> {
        self.thing_name.as_deref()
    }
    /// <p>The entity type from which to disassociate the thing.</p>
    pub fn entity_type(&self) -> ::std::option::Option<&crate::types::EntityType> {
        self.entity_type.as_ref()
    }
}
impl DissociateEntityFromThingInput {
    /// Creates a new builder-style object to manufacture [`DissociateEntityFromThingInput`](crate::operation::dissociate_entity_from_thing::DissociateEntityFromThingInput).
    pub fn builder() -> crate::operation::dissociate_entity_from_thing::builders::DissociateEntityFromThingInputBuilder {
        crate::operation::dissociate_entity_from_thing::builders::DissociateEntityFromThingInputBuilder::default()
    }
}

/// A builder for [`DissociateEntityFromThingInput`](crate::operation::dissociate_entity_from_thing::DissociateEntityFromThingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DissociateEntityFromThingInputBuilder {
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) entity_type: ::std::option::Option<crate::types::EntityType>,
}
impl DissociateEntityFromThingInputBuilder {
    /// <p>The name of the thing to disassociate.</p>
    /// This field is required.
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the thing to disassociate.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the thing to disassociate.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// <p>The entity type from which to disassociate the thing.</p>
    /// This field is required.
    pub fn entity_type(mut self, input: crate::types::EntityType) -> Self {
        self.entity_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entity type from which to disassociate the thing.</p>
    pub fn set_entity_type(mut self, input: ::std::option::Option<crate::types::EntityType>) -> Self {
        self.entity_type = input;
        self
    }
    /// <p>The entity type from which to disassociate the thing.</p>
    pub fn get_entity_type(&self) -> &::std::option::Option<crate::types::EntityType> {
        &self.entity_type
    }
    /// Consumes the builder and constructs a [`DissociateEntityFromThingInput`](crate::operation::dissociate_entity_from_thing::DissociateEntityFromThingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::dissociate_entity_from_thing::DissociateEntityFromThingInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::dissociate_entity_from_thing::DissociateEntityFromThingInput {
            thing_name: self.thing_name,
            entity_type: self.entity_type,
        })
    }
}
