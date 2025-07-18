// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteHomeRegionControlInput {
    /// <p>A unique identifier that's generated for each home region control. It's always a string that begins with "hrc-" followed by 12 lowercase letters and numbers.</p>
    pub control_id: ::std::option::Option<::std::string::String>,
}
impl DeleteHomeRegionControlInput {
    /// <p>A unique identifier that's generated for each home region control. It's always a string that begins with "hrc-" followed by 12 lowercase letters and numbers.</p>
    pub fn control_id(&self) -> ::std::option::Option<&str> {
        self.control_id.as_deref()
    }
}
impl DeleteHomeRegionControlInput {
    /// Creates a new builder-style object to manufacture [`DeleteHomeRegionControlInput`](crate::operation::delete_home_region_control::DeleteHomeRegionControlInput).
    pub fn builder() -> crate::operation::delete_home_region_control::builders::DeleteHomeRegionControlInputBuilder {
        crate::operation::delete_home_region_control::builders::DeleteHomeRegionControlInputBuilder::default()
    }
}

/// A builder for [`DeleteHomeRegionControlInput`](crate::operation::delete_home_region_control::DeleteHomeRegionControlInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteHomeRegionControlInputBuilder {
    pub(crate) control_id: ::std::option::Option<::std::string::String>,
}
impl DeleteHomeRegionControlInputBuilder {
    /// <p>A unique identifier that's generated for each home region control. It's always a string that begins with "hrc-" followed by 12 lowercase letters and numbers.</p>
    /// This field is required.
    pub fn control_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier that's generated for each home region control. It's always a string that begins with "hrc-" followed by 12 lowercase letters and numbers.</p>
    pub fn set_control_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_id = input;
        self
    }
    /// <p>A unique identifier that's generated for each home region control. It's always a string that begins with "hrc-" followed by 12 lowercase letters and numbers.</p>
    pub fn get_control_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_id
    }
    /// Consumes the builder and constructs a [`DeleteHomeRegionControlInput`](crate::operation::delete_home_region_control::DeleteHomeRegionControlInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_home_region_control::DeleteHomeRegionControlInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_home_region_control::DeleteHomeRegionControlInput { control_id: self.control_id })
    }
}
