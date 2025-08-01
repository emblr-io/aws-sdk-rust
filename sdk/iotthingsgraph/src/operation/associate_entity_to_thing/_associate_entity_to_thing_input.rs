// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateEntityToThingInput {
    /// <p>The name of the thing to which the entity is to be associated.</p>
    pub thing_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the device to be associated with the thing.</p>
    /// <p>The ID should be in the following format.</p>
    /// <p><code>urn:tdm:REGION/ACCOUNT ID/default:device:DEVICENAME</code></p>
    pub entity_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the user's namespace. Defaults to the latest version of the user's namespace.</p>
    pub namespace_version: ::std::option::Option<i64>,
}
impl AssociateEntityToThingInput {
    /// <p>The name of the thing to which the entity is to be associated.</p>
    pub fn thing_name(&self) -> ::std::option::Option<&str> {
        self.thing_name.as_deref()
    }
    /// <p>The ID of the device to be associated with the thing.</p>
    /// <p>The ID should be in the following format.</p>
    /// <p><code>urn:tdm:REGION/ACCOUNT ID/default:device:DEVICENAME</code></p>
    pub fn entity_id(&self) -> ::std::option::Option<&str> {
        self.entity_id.as_deref()
    }
    /// <p>The version of the user's namespace. Defaults to the latest version of the user's namespace.</p>
    pub fn namespace_version(&self) -> ::std::option::Option<i64> {
        self.namespace_version
    }
}
impl AssociateEntityToThingInput {
    /// Creates a new builder-style object to manufacture [`AssociateEntityToThingInput`](crate::operation::associate_entity_to_thing::AssociateEntityToThingInput).
    pub fn builder() -> crate::operation::associate_entity_to_thing::builders::AssociateEntityToThingInputBuilder {
        crate::operation::associate_entity_to_thing::builders::AssociateEntityToThingInputBuilder::default()
    }
}

/// A builder for [`AssociateEntityToThingInput`](crate::operation::associate_entity_to_thing::AssociateEntityToThingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateEntityToThingInputBuilder {
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) entity_id: ::std::option::Option<::std::string::String>,
    pub(crate) namespace_version: ::std::option::Option<i64>,
}
impl AssociateEntityToThingInputBuilder {
    /// <p>The name of the thing to which the entity is to be associated.</p>
    /// This field is required.
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the thing to which the entity is to be associated.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the thing to which the entity is to be associated.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// <p>The ID of the device to be associated with the thing.</p>
    /// <p>The ID should be in the following format.</p>
    /// <p><code>urn:tdm:REGION/ACCOUNT ID/default:device:DEVICENAME</code></p>
    /// This field is required.
    pub fn entity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the device to be associated with the thing.</p>
    /// <p>The ID should be in the following format.</p>
    /// <p><code>urn:tdm:REGION/ACCOUNT ID/default:device:DEVICENAME</code></p>
    pub fn set_entity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id = input;
        self
    }
    /// <p>The ID of the device to be associated with the thing.</p>
    /// <p>The ID should be in the following format.</p>
    /// <p><code>urn:tdm:REGION/ACCOUNT ID/default:device:DEVICENAME</code></p>
    pub fn get_entity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id
    }
    /// <p>The version of the user's namespace. Defaults to the latest version of the user's namespace.</p>
    pub fn namespace_version(mut self, input: i64) -> Self {
        self.namespace_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the user's namespace. Defaults to the latest version of the user's namespace.</p>
    pub fn set_namespace_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.namespace_version = input;
        self
    }
    /// <p>The version of the user's namespace. Defaults to the latest version of the user's namespace.</p>
    pub fn get_namespace_version(&self) -> &::std::option::Option<i64> {
        &self.namespace_version
    }
    /// Consumes the builder and constructs a [`AssociateEntityToThingInput`](crate::operation::associate_entity_to_thing::AssociateEntityToThingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_entity_to_thing::AssociateEntityToThingInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::associate_entity_to_thing::AssociateEntityToThingInput {
            thing_name: self.thing_name,
            entity_id: self.entity_id,
            namespace_version: self.namespace_version,
        })
    }
}
