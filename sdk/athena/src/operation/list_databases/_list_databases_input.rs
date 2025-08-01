// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDatabasesInput {
    /// <p>The name of the data catalog that contains the databases to return.</p>
    pub catalog_name: ::std::option::Option<::std::string::String>,
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the <code>NextToken</code> from the response object of the previous page call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub work_group: ::std::option::Option<::std::string::String>,
}
impl ListDatabasesInput {
    /// <p>The name of the data catalog that contains the databases to return.</p>
    pub fn catalog_name(&self) -> ::std::option::Option<&str> {
        self.catalog_name.as_deref()
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the <code>NextToken</code> from the response object of the previous page call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Specifies the maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn work_group(&self) -> ::std::option::Option<&str> {
        self.work_group.as_deref()
    }
}
impl ListDatabasesInput {
    /// Creates a new builder-style object to manufacture [`ListDatabasesInput`](crate::operation::list_databases::ListDatabasesInput).
    pub fn builder() -> crate::operation::list_databases::builders::ListDatabasesInputBuilder {
        crate::operation::list_databases::builders::ListDatabasesInputBuilder::default()
    }
}

/// A builder for [`ListDatabasesInput`](crate::operation::list_databases::ListDatabasesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDatabasesInputBuilder {
    pub(crate) catalog_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) work_group: ::std::option::Option<::std::string::String>,
}
impl ListDatabasesInputBuilder {
    /// <p>The name of the data catalog that contains the databases to return.</p>
    /// This field is required.
    pub fn catalog_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data catalog that contains the databases to return.</p>
    pub fn set_catalog_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_name = input;
        self
    }
    /// <p>The name of the data catalog that contains the databases to return.</p>
    pub fn get_catalog_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_name
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the <code>NextToken</code> from the response object of the previous page call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the <code>NextToken</code> from the response object of the previous page call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the <code>NextToken</code> from the response object of the previous page call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Specifies the maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Specifies the maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn work_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.work_group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn set_work_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.work_group = input;
        self
    }
    /// <p>The name of the workgroup for which the metadata is being fetched. Required if requesting an IAM Identity Center enabled Glue Data Catalog.</p>
    pub fn get_work_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.work_group
    }
    /// Consumes the builder and constructs a [`ListDatabasesInput`](crate::operation::list_databases::ListDatabasesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_databases::ListDatabasesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_databases::ListDatabasesInput {
            catalog_name: self.catalog_name,
            next_token: self.next_token,
            max_results: self.max_results,
            work_group: self.work_group,
        })
    }
}
