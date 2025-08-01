// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the thing and the type of relation it has with the principal.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PrincipalThingObject {
    /// <p>The name of the thing.</p>
    pub thing_name: ::std::string::String,
    /// <p>The type of the relation you want to specify when you attach a principal to a thing. The value defaults to <code>NON_EXCLUSIVE_THING</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub thing_principal_type: ::std::option::Option<crate::types::ThingPrincipalType>,
}
impl PrincipalThingObject {
    /// <p>The name of the thing.</p>
    pub fn thing_name(&self) -> &str {
        use std::ops::Deref;
        self.thing_name.deref()
    }
    /// <p>The type of the relation you want to specify when you attach a principal to a thing. The value defaults to <code>NON_EXCLUSIVE_THING</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn thing_principal_type(&self) -> ::std::option::Option<&crate::types::ThingPrincipalType> {
        self.thing_principal_type.as_ref()
    }
}
impl PrincipalThingObject {
    /// Creates a new builder-style object to manufacture [`PrincipalThingObject`](crate::types::PrincipalThingObject).
    pub fn builder() -> crate::types::builders::PrincipalThingObjectBuilder {
        crate::types::builders::PrincipalThingObjectBuilder::default()
    }
}

/// A builder for [`PrincipalThingObject`](crate::types::PrincipalThingObject).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PrincipalThingObjectBuilder {
    pub(crate) thing_name: ::std::option::Option<::std::string::String>,
    pub(crate) thing_principal_type: ::std::option::Option<crate::types::ThingPrincipalType>,
}
impl PrincipalThingObjectBuilder {
    /// <p>The name of the thing.</p>
    /// This field is required.
    pub fn thing_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the thing.</p>
    pub fn set_thing_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_name = input;
        self
    }
    /// <p>The name of the thing.</p>
    pub fn get_thing_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_name
    }
    /// <p>The type of the relation you want to specify when you attach a principal to a thing. The value defaults to <code>NON_EXCLUSIVE_THING</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn thing_principal_type(mut self, input: crate::types::ThingPrincipalType) -> Self {
        self.thing_principal_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the relation you want to specify when you attach a principal to a thing. The value defaults to <code>NON_EXCLUSIVE_THING</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn set_thing_principal_type(mut self, input: ::std::option::Option<crate::types::ThingPrincipalType>) -> Self {
        self.thing_principal_type = input;
        self
    }
    /// <p>The type of the relation you want to specify when you attach a principal to a thing. The value defaults to <code>NON_EXCLUSIVE_THING</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing, exclusively. The thing will be the only thing that’s attached to the principal.</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p><code>NON_EXCLUSIVE_THING</code> - Attaches the specified principal to the specified thing. Multiple things can be attached to the principal.</p></li>
    /// </ul>
    pub fn get_thing_principal_type(&self) -> &::std::option::Option<crate::types::ThingPrincipalType> {
        &self.thing_principal_type
    }
    /// Consumes the builder and constructs a [`PrincipalThingObject`](crate::types::PrincipalThingObject).
    /// This method will fail if any of the following fields are not set:
    /// - [`thing_name`](crate::types::builders::PrincipalThingObjectBuilder::thing_name)
    pub fn build(self) -> ::std::result::Result<crate::types::PrincipalThingObject, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PrincipalThingObject {
            thing_name: self.thing_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "thing_name",
                    "thing_name was not specified but it is required when building PrincipalThingObject",
                )
            })?,
            thing_principal_type: self.thing_principal_type,
        })
    }
}
