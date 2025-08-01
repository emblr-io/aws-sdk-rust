// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSegmentReferencesOutput {
    /// <p>An array of structures, where each structure contains information about one experiment or launch that uses this segment.</p>
    pub referenced_by: ::std::option::Option<::std::vec::Vec<crate::types::RefResource>>,
    /// <p>The token to use in a subsequent <code>ListSegmentReferences</code> operation to return the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSegmentReferencesOutput {
    /// <p>An array of structures, where each structure contains information about one experiment or launch that uses this segment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.referenced_by.is_none()`.
    pub fn referenced_by(&self) -> &[crate::types::RefResource] {
        self.referenced_by.as_deref().unwrap_or_default()
    }
    /// <p>The token to use in a subsequent <code>ListSegmentReferences</code> operation to return the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListSegmentReferencesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListSegmentReferencesOutput {
    /// Creates a new builder-style object to manufacture [`ListSegmentReferencesOutput`](crate::operation::list_segment_references::ListSegmentReferencesOutput).
    pub fn builder() -> crate::operation::list_segment_references::builders::ListSegmentReferencesOutputBuilder {
        crate::operation::list_segment_references::builders::ListSegmentReferencesOutputBuilder::default()
    }
}

/// A builder for [`ListSegmentReferencesOutput`](crate::operation::list_segment_references::ListSegmentReferencesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSegmentReferencesOutputBuilder {
    pub(crate) referenced_by: ::std::option::Option<::std::vec::Vec<crate::types::RefResource>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListSegmentReferencesOutputBuilder {
    /// Appends an item to `referenced_by`.
    ///
    /// To override the contents of this collection use [`set_referenced_by`](Self::set_referenced_by).
    ///
    /// <p>An array of structures, where each structure contains information about one experiment or launch that uses this segment.</p>
    pub fn referenced_by(mut self, input: crate::types::RefResource) -> Self {
        let mut v = self.referenced_by.unwrap_or_default();
        v.push(input);
        self.referenced_by = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of structures, where each structure contains information about one experiment or launch that uses this segment.</p>
    pub fn set_referenced_by(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RefResource>>) -> Self {
        self.referenced_by = input;
        self
    }
    /// <p>An array of structures, where each structure contains information about one experiment or launch that uses this segment.</p>
    pub fn get_referenced_by(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RefResource>> {
        &self.referenced_by
    }
    /// <p>The token to use in a subsequent <code>ListSegmentReferences</code> operation to return the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use in a subsequent <code>ListSegmentReferences</code> operation to return the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use in a subsequent <code>ListSegmentReferences</code> operation to return the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListSegmentReferencesOutput`](crate::operation::list_segment_references::ListSegmentReferencesOutput).
    pub fn build(self) -> crate::operation::list_segment_references::ListSegmentReferencesOutput {
        crate::operation::list_segment_references::ListSegmentReferencesOutput {
            referenced_by: self.referenced_by,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
