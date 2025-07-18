// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFileSystemAssociationsOutput {
    /// <p>If the request includes <code>Marker</code>, the response returns that value in this field.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>If a value is present, there are more file system associations to return. In a subsequent request, use <code>NextMarker</code> as the value for <code>Marker</code> to retrieve the next set of file system associations.</p>
    pub next_marker: ::std::option::Option<::std::string::String>,
    /// <p>An array of information about the Amazon FSx gateway's file system associations.</p>
    pub file_system_association_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::FileSystemAssociationSummary>>,
    _request_id: Option<String>,
}
impl ListFileSystemAssociationsOutput {
    /// <p>If the request includes <code>Marker</code>, the response returns that value in this field.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>If a value is present, there are more file system associations to return. In a subsequent request, use <code>NextMarker</code> as the value for <code>Marker</code> to retrieve the next set of file system associations.</p>
    pub fn next_marker(&self) -> ::std::option::Option<&str> {
        self.next_marker.as_deref()
    }
    /// <p>An array of information about the Amazon FSx gateway's file system associations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.file_system_association_summary_list.is_none()`.
    pub fn file_system_association_summary_list(&self) -> &[crate::types::FileSystemAssociationSummary] {
        self.file_system_association_summary_list.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListFileSystemAssociationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFileSystemAssociationsOutput {
    /// Creates a new builder-style object to manufacture [`ListFileSystemAssociationsOutput`](crate::operation::list_file_system_associations::ListFileSystemAssociationsOutput).
    pub fn builder() -> crate::operation::list_file_system_associations::builders::ListFileSystemAssociationsOutputBuilder {
        crate::operation::list_file_system_associations::builders::ListFileSystemAssociationsOutputBuilder::default()
    }
}

/// A builder for [`ListFileSystemAssociationsOutput`](crate::operation::list_file_system_associations::ListFileSystemAssociationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFileSystemAssociationsOutputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) next_marker: ::std::option::Option<::std::string::String>,
    pub(crate) file_system_association_summary_list: ::std::option::Option<::std::vec::Vec<crate::types::FileSystemAssociationSummary>>,
    _request_id: Option<String>,
}
impl ListFileSystemAssociationsOutputBuilder {
    /// <p>If the request includes <code>Marker</code>, the response returns that value in this field.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the request includes <code>Marker</code>, the response returns that value in this field.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>If the request includes <code>Marker</code>, the response returns that value in this field.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>If a value is present, there are more file system associations to return. In a subsequent request, use <code>NextMarker</code> as the value for <code>Marker</code> to retrieve the next set of file system associations.</p>
    pub fn next_marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If a value is present, there are more file system associations to return. In a subsequent request, use <code>NextMarker</code> as the value for <code>Marker</code> to retrieve the next set of file system associations.</p>
    pub fn set_next_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_marker = input;
        self
    }
    /// <p>If a value is present, there are more file system associations to return. In a subsequent request, use <code>NextMarker</code> as the value for <code>Marker</code> to retrieve the next set of file system associations.</p>
    pub fn get_next_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_marker
    }
    /// Appends an item to `file_system_association_summary_list`.
    ///
    /// To override the contents of this collection use [`set_file_system_association_summary_list`](Self::set_file_system_association_summary_list).
    ///
    /// <p>An array of information about the Amazon FSx gateway's file system associations.</p>
    pub fn file_system_association_summary_list(mut self, input: crate::types::FileSystemAssociationSummary) -> Self {
        let mut v = self.file_system_association_summary_list.unwrap_or_default();
        v.push(input);
        self.file_system_association_summary_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of information about the Amazon FSx gateway's file system associations.</p>
    pub fn set_file_system_association_summary_list(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::FileSystemAssociationSummary>>,
    ) -> Self {
        self.file_system_association_summary_list = input;
        self
    }
    /// <p>An array of information about the Amazon FSx gateway's file system associations.</p>
    pub fn get_file_system_association_summary_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FileSystemAssociationSummary>> {
        &self.file_system_association_summary_list
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListFileSystemAssociationsOutput`](crate::operation::list_file_system_associations::ListFileSystemAssociationsOutput).
    pub fn build(self) -> crate::operation::list_file_system_associations::ListFileSystemAssociationsOutput {
        crate::operation::list_file_system_associations::ListFileSystemAssociationsOutput {
            marker: self.marker,
            next_marker: self.next_marker,
            file_system_association_summary_list: self.file_system_association_summary_list,
            _request_id: self._request_id,
        }
    }
}
