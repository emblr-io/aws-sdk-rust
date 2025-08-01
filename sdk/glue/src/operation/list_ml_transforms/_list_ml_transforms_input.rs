// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMlTransformsInput {
    /// <p>A continuation token, if this is a continuation request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum size of a list to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A <code>TransformFilterCriteria</code> used to filter the machine learning transforms.</p>
    pub filter: ::std::option::Option<crate::types::TransformFilterCriteria>,
    /// <p>A <code>TransformSortCriteria</code> used to sort the machine learning transforms.</p>
    pub sort: ::std::option::Option<crate::types::TransformSortCriteria>,
    /// <p>Specifies to return only these tagged resources.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ListMlTransformsInput {
    /// <p>A continuation token, if this is a continuation request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum size of a list to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A <code>TransformFilterCriteria</code> used to filter the machine learning transforms.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::TransformFilterCriteria> {
        self.filter.as_ref()
    }
    /// <p>A <code>TransformSortCriteria</code> used to sort the machine learning transforms.</p>
    pub fn sort(&self) -> ::std::option::Option<&crate::types::TransformSortCriteria> {
        self.sort.as_ref()
    }
    /// <p>Specifies to return only these tagged resources.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ListMlTransformsInput {
    /// Creates a new builder-style object to manufacture [`ListMlTransformsInput`](crate::operation::list_ml_transforms::ListMlTransformsInput).
    pub fn builder() -> crate::operation::list_ml_transforms::builders::ListMlTransformsInputBuilder {
        crate::operation::list_ml_transforms::builders::ListMlTransformsInputBuilder::default()
    }
}

/// A builder for [`ListMlTransformsInput`](crate::operation::list_ml_transforms::ListMlTransformsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMlTransformsInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) filter: ::std::option::Option<crate::types::TransformFilterCriteria>,
    pub(crate) sort: ::std::option::Option<crate::types::TransformSortCriteria>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ListMlTransformsInputBuilder {
    /// <p>A continuation token, if this is a continuation request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, if this is a continuation request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, if this is a continuation request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum size of a list to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size of a list to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum size of a list to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A <code>TransformFilterCriteria</code> used to filter the machine learning transforms.</p>
    pub fn filter(mut self, input: crate::types::TransformFilterCriteria) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>TransformFilterCriteria</code> used to filter the machine learning transforms.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::TransformFilterCriteria>) -> Self {
        self.filter = input;
        self
    }
    /// <p>A <code>TransformFilterCriteria</code> used to filter the machine learning transforms.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::TransformFilterCriteria> {
        &self.filter
    }
    /// <p>A <code>TransformSortCriteria</code> used to sort the machine learning transforms.</p>
    pub fn sort(mut self, input: crate::types::TransformSortCriteria) -> Self {
        self.sort = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>TransformSortCriteria</code> used to sort the machine learning transforms.</p>
    pub fn set_sort(mut self, input: ::std::option::Option<crate::types::TransformSortCriteria>) -> Self {
        self.sort = input;
        self
    }
    /// <p>A <code>TransformSortCriteria</code> used to sort the machine learning transforms.</p>
    pub fn get_sort(&self) -> &::std::option::Option<crate::types::TransformSortCriteria> {
        &self.sort
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Specifies to return only these tagged resources.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Specifies to return only these tagged resources.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Specifies to return only these tagged resources.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ListMlTransformsInput`](crate::operation::list_ml_transforms::ListMlTransformsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_ml_transforms::ListMlTransformsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_ml_transforms::ListMlTransformsInput {
            next_token: self.next_token,
            max_results: self.max_results,
            filter: self.filter,
            sort: self.sort,
            tags: self.tags,
        })
    }
}
