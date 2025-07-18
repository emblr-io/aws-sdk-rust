// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTableMetadataOutput {
    /// <p>A list of table metadata.</p>
    pub table_metadata_list: ::std::option::Option<::std::vec::Vec<crate::types::TableMetadata>>,
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListTableMetadataOutput {
    /// <p>A list of table metadata.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.table_metadata_list.is_none()`.
    pub fn table_metadata_list(&self) -> &[crate::types::TableMetadata] {
        self.table_metadata_list.as_deref().unwrap_or_default()
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListTableMetadataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListTableMetadataOutput {
    /// Creates a new builder-style object to manufacture [`ListTableMetadataOutput`](crate::operation::list_table_metadata::ListTableMetadataOutput).
    pub fn builder() -> crate::operation::list_table_metadata::builders::ListTableMetadataOutputBuilder {
        crate::operation::list_table_metadata::builders::ListTableMetadataOutputBuilder::default()
    }
}

/// A builder for [`ListTableMetadataOutput`](crate::operation::list_table_metadata::ListTableMetadataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTableMetadataOutputBuilder {
    pub(crate) table_metadata_list: ::std::option::Option<::std::vec::Vec<crate::types::TableMetadata>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListTableMetadataOutputBuilder {
    /// Appends an item to `table_metadata_list`.
    ///
    /// To override the contents of this collection use [`set_table_metadata_list`](Self::set_table_metadata_list).
    ///
    /// <p>A list of table metadata.</p>
    pub fn table_metadata_list(mut self, input: crate::types::TableMetadata) -> Self {
        let mut v = self.table_metadata_list.unwrap_or_default();
        v.push(input);
        self.table_metadata_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of table metadata.</p>
    pub fn set_table_metadata_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TableMetadata>>) -> Self {
        self.table_metadata_list = input;
        self
    }
    /// <p>A list of table metadata.</p>
    pub fn get_table_metadata_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TableMetadata>> {
        &self.table_metadata_list
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token generated by the Athena service that specifies where to continue pagination if a previous request was truncated. To obtain the next set of pages, pass in the NextToken from the response object of the previous page call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListTableMetadataOutput`](crate::operation::list_table_metadata::ListTableMetadataOutput).
    pub fn build(self) -> crate::operation::list_table_metadata::ListTableMetadataOutput {
        crate::operation::list_table_metadata::ListTableMetadataOutput {
            table_metadata_list: self.table_metadata_list,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
