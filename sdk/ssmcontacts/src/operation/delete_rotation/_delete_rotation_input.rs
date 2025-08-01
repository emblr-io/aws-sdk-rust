// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRotationInput {
    /// <p>The Amazon Resource Name (ARN) of the on-call rotation to delete.</p>
    pub rotation_id: ::std::option::Option<::std::string::String>,
}
impl DeleteRotationInput {
    /// <p>The Amazon Resource Name (ARN) of the on-call rotation to delete.</p>
    pub fn rotation_id(&self) -> ::std::option::Option<&str> {
        self.rotation_id.as_deref()
    }
}
impl DeleteRotationInput {
    /// Creates a new builder-style object to manufacture [`DeleteRotationInput`](crate::operation::delete_rotation::DeleteRotationInput).
    pub fn builder() -> crate::operation::delete_rotation::builders::DeleteRotationInputBuilder {
        crate::operation::delete_rotation::builders::DeleteRotationInputBuilder::default()
    }
}

/// A builder for [`DeleteRotationInput`](crate::operation::delete_rotation::DeleteRotationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRotationInputBuilder {
    pub(crate) rotation_id: ::std::option::Option<::std::string::String>,
}
impl DeleteRotationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the on-call rotation to delete.</p>
    /// This field is required.
    pub fn rotation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rotation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the on-call rotation to delete.</p>
    pub fn set_rotation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rotation_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the on-call rotation to delete.</p>
    pub fn get_rotation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.rotation_id
    }
    /// Consumes the builder and constructs a [`DeleteRotationInput`](crate::operation::delete_rotation::DeleteRotationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_rotation::DeleteRotationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_rotation::DeleteRotationInput {
            rotation_id: self.rotation_id,
        })
    }
}
