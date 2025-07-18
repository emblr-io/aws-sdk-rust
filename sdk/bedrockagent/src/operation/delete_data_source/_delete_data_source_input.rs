// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDataSourceInput {
    /// <p>The unique identifier of the knowledge base from which to delete the data source.</p>
    pub knowledge_base_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the data source to delete.</p>
    pub data_source_id: ::std::option::Option<::std::string::String>,
}
impl DeleteDataSourceInput {
    /// <p>The unique identifier of the knowledge base from which to delete the data source.</p>
    pub fn knowledge_base_id(&self) -> ::std::option::Option<&str> {
        self.knowledge_base_id.as_deref()
    }
    /// <p>The unique identifier of the data source to delete.</p>
    pub fn data_source_id(&self) -> ::std::option::Option<&str> {
        self.data_source_id.as_deref()
    }
}
impl DeleteDataSourceInput {
    /// Creates a new builder-style object to manufacture [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
    pub fn builder() -> crate::operation::delete_data_source::builders::DeleteDataSourceInputBuilder {
        crate::operation::delete_data_source::builders::DeleteDataSourceInputBuilder::default()
    }
}

/// A builder for [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDataSourceInputBuilder {
    pub(crate) knowledge_base_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_source_id: ::std::option::Option<::std::string::String>,
}
impl DeleteDataSourceInputBuilder {
    /// <p>The unique identifier of the knowledge base from which to delete the data source.</p>
    /// This field is required.
    pub fn knowledge_base_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the knowledge base from which to delete the data source.</p>
    pub fn set_knowledge_base_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_id = input;
        self
    }
    /// <p>The unique identifier of the knowledge base from which to delete the data source.</p>
    pub fn get_knowledge_base_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_id
    }
    /// <p>The unique identifier of the data source to delete.</p>
    /// This field is required.
    pub fn data_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the data source to delete.</p>
    pub fn set_data_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_id = input;
        self
    }
    /// <p>The unique identifier of the data source to delete.</p>
    pub fn get_data_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_id
    }
    /// Consumes the builder and constructs a [`DeleteDataSourceInput`](crate::operation::delete_data_source::DeleteDataSourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_data_source::DeleteDataSourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_data_source::DeleteDataSourceInput {
            knowledge_base_id: self.knowledge_base_id,
            data_source_id: self.data_source_id,
        })
    }
}
