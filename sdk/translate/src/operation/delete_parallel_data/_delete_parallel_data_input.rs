// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteParallelDataInput {
    /// <p>The name of the parallel data resource that is being deleted.</p>
    pub name: ::std::option::Option<::std::string::String>,
}
impl DeleteParallelDataInput {
    /// <p>The name of the parallel data resource that is being deleted.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl DeleteParallelDataInput {
    /// Creates a new builder-style object to manufacture [`DeleteParallelDataInput`](crate::operation::delete_parallel_data::DeleteParallelDataInput).
    pub fn builder() -> crate::operation::delete_parallel_data::builders::DeleteParallelDataInputBuilder {
        crate::operation::delete_parallel_data::builders::DeleteParallelDataInputBuilder::default()
    }
}

/// A builder for [`DeleteParallelDataInput`](crate::operation::delete_parallel_data::DeleteParallelDataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteParallelDataInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl DeleteParallelDataInputBuilder {
    /// <p>The name of the parallel data resource that is being deleted.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the parallel data resource that is being deleted.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the parallel data resource that is being deleted.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`DeleteParallelDataInput`](crate::operation::delete_parallel_data::DeleteParallelDataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_parallel_data::DeleteParallelDataInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_parallel_data::DeleteParallelDataInput { name: self.name })
    }
}
