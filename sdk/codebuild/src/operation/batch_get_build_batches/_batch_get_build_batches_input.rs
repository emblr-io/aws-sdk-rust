// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetBuildBatchesInput {
    /// <p>An array that contains the batch build identifiers to retrieve.</p>
    pub ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetBuildBatchesInput {
    /// <p>An array that contains the batch build identifiers to retrieve.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ids.is_none()`.
    pub fn ids(&self) -> &[::std::string::String] {
        self.ids.as_deref().unwrap_or_default()
    }
}
impl BatchGetBuildBatchesInput {
    /// Creates a new builder-style object to manufacture [`BatchGetBuildBatchesInput`](crate::operation::batch_get_build_batches::BatchGetBuildBatchesInput).
    pub fn builder() -> crate::operation::batch_get_build_batches::builders::BatchGetBuildBatchesInputBuilder {
        crate::operation::batch_get_build_batches::builders::BatchGetBuildBatchesInputBuilder::default()
    }
}

/// A builder for [`BatchGetBuildBatchesInput`](crate::operation::batch_get_build_batches::BatchGetBuildBatchesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetBuildBatchesInputBuilder {
    pub(crate) ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetBuildBatchesInputBuilder {
    /// Appends an item to `ids`.
    ///
    /// To override the contents of this collection use [`set_ids`](Self::set_ids).
    ///
    /// <p>An array that contains the batch build identifiers to retrieve.</p>
    pub fn ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ids.unwrap_or_default();
        v.push(input.into());
        self.ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that contains the batch build identifiers to retrieve.</p>
    pub fn set_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ids = input;
        self
    }
    /// <p>An array that contains the batch build identifiers to retrieve.</p>
    pub fn get_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ids
    }
    /// Consumes the builder and constructs a [`BatchGetBuildBatchesInput`](crate::operation::batch_get_build_batches::BatchGetBuildBatchesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_get_build_batches::BatchGetBuildBatchesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::batch_get_build_batches::BatchGetBuildBatchesInput { ids: self.ids })
    }
}
