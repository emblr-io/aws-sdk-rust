// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelZonalShiftInput {
    /// <p>The internally-generated identifier of a zonal shift.</p>
    pub zonal_shift_id: ::std::option::Option<::std::string::String>,
}
impl CancelZonalShiftInput {
    /// <p>The internally-generated identifier of a zonal shift.</p>
    pub fn zonal_shift_id(&self) -> ::std::option::Option<&str> {
        self.zonal_shift_id.as_deref()
    }
}
impl CancelZonalShiftInput {
    /// Creates a new builder-style object to manufacture [`CancelZonalShiftInput`](crate::operation::cancel_zonal_shift::CancelZonalShiftInput).
    pub fn builder() -> crate::operation::cancel_zonal_shift::builders::CancelZonalShiftInputBuilder {
        crate::operation::cancel_zonal_shift::builders::CancelZonalShiftInputBuilder::default()
    }
}

/// A builder for [`CancelZonalShiftInput`](crate::operation::cancel_zonal_shift::CancelZonalShiftInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelZonalShiftInputBuilder {
    pub(crate) zonal_shift_id: ::std::option::Option<::std::string::String>,
}
impl CancelZonalShiftInputBuilder {
    /// <p>The internally-generated identifier of a zonal shift.</p>
    /// This field is required.
    pub fn zonal_shift_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.zonal_shift_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The internally-generated identifier of a zonal shift.</p>
    pub fn set_zonal_shift_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.zonal_shift_id = input;
        self
    }
    /// <p>The internally-generated identifier of a zonal shift.</p>
    pub fn get_zonal_shift_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.zonal_shift_id
    }
    /// Consumes the builder and constructs a [`CancelZonalShiftInput`](crate::operation::cancel_zonal_shift::CancelZonalShiftInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_zonal_shift::CancelZonalShiftInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_zonal_shift::CancelZonalShiftInput {
            zonal_shift_id: self.zonal_shift_id,
        })
    }
}
