// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFeaturedResultsSetInput {
    /// <p>The identifier of the index used for featuring results.</p>
    pub index_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the set of featured results that you want to get information on.</p>
    pub featured_results_set_id: ::std::option::Option<::std::string::String>,
}
impl DescribeFeaturedResultsSetInput {
    /// <p>The identifier of the index used for featuring results.</p>
    pub fn index_id(&self) -> ::std::option::Option<&str> {
        self.index_id.as_deref()
    }
    /// <p>The identifier of the set of featured results that you want to get information on.</p>
    pub fn featured_results_set_id(&self) -> ::std::option::Option<&str> {
        self.featured_results_set_id.as_deref()
    }
}
impl DescribeFeaturedResultsSetInput {
    /// Creates a new builder-style object to manufacture [`DescribeFeaturedResultsSetInput`](crate::operation::describe_featured_results_set::DescribeFeaturedResultsSetInput).
    pub fn builder() -> crate::operation::describe_featured_results_set::builders::DescribeFeaturedResultsSetInputBuilder {
        crate::operation::describe_featured_results_set::builders::DescribeFeaturedResultsSetInputBuilder::default()
    }
}

/// A builder for [`DescribeFeaturedResultsSetInput`](crate::operation::describe_featured_results_set::DescribeFeaturedResultsSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFeaturedResultsSetInputBuilder {
    pub(crate) index_id: ::std::option::Option<::std::string::String>,
    pub(crate) featured_results_set_id: ::std::option::Option<::std::string::String>,
}
impl DescribeFeaturedResultsSetInputBuilder {
    /// <p>The identifier of the index used for featuring results.</p>
    /// This field is required.
    pub fn index_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the index used for featuring results.</p>
    pub fn set_index_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_id = input;
        self
    }
    /// <p>The identifier of the index used for featuring results.</p>
    pub fn get_index_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_id
    }
    /// <p>The identifier of the set of featured results that you want to get information on.</p>
    /// This field is required.
    pub fn featured_results_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.featured_results_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the set of featured results that you want to get information on.</p>
    pub fn set_featured_results_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.featured_results_set_id = input;
        self
    }
    /// <p>The identifier of the set of featured results that you want to get information on.</p>
    pub fn get_featured_results_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.featured_results_set_id
    }
    /// Consumes the builder and constructs a [`DescribeFeaturedResultsSetInput`](crate::operation::describe_featured_results_set::DescribeFeaturedResultsSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_featured_results_set::DescribeFeaturedResultsSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_featured_results_set::DescribeFeaturedResultsSetInput {
            index_id: self.index_id,
            featured_results_set_id: self.featured_results_set_id,
        })
    }
}
