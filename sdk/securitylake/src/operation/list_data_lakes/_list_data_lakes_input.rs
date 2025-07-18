// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDataLakesInput {
    /// <p>The list of Regions where Security Lake is enabled.</p>
    pub regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListDataLakesInput {
    /// <p>The list of Regions where Security Lake is enabled.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.regions.is_none()`.
    pub fn regions(&self) -> &[::std::string::String] {
        self.regions.as_deref().unwrap_or_default()
    }
}
impl ListDataLakesInput {
    /// Creates a new builder-style object to manufacture [`ListDataLakesInput`](crate::operation::list_data_lakes::ListDataLakesInput).
    pub fn builder() -> crate::operation::list_data_lakes::builders::ListDataLakesInputBuilder {
        crate::operation::list_data_lakes::builders::ListDataLakesInputBuilder::default()
    }
}

/// A builder for [`ListDataLakesInput`](crate::operation::list_data_lakes::ListDataLakesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDataLakesInputBuilder {
    pub(crate) regions: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ListDataLakesInputBuilder {
    /// Appends an item to `regions`.
    ///
    /// To override the contents of this collection use [`set_regions`](Self::set_regions).
    ///
    /// <p>The list of Regions where Security Lake is enabled.</p>
    pub fn regions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.regions.unwrap_or_default();
        v.push(input.into());
        self.regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of Regions where Security Lake is enabled.</p>
    pub fn set_regions(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.regions = input;
        self
    }
    /// <p>The list of Regions where Security Lake is enabled.</p>
    pub fn get_regions(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.regions
    }
    /// Consumes the builder and constructs a [`ListDataLakesInput`](crate::operation::list_data_lakes::ListDataLakesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_data_lakes::ListDataLakesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_data_lakes::ListDataLakesInput { regions: self.regions })
    }
}
