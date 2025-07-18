// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSnapshotsOutput {
    /// <p>An array of snapshots.</p>
    pub snapshots: ::std::option::Option<::std::vec::Vec<crate::types::Snapshot>>,
    /// <p>(Optional) Opaque pagination token returned from a previous operation (String). If present, this token indicates from what point you can continue processing the request, where the previous <code>NextToken</code> value left off.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeSnapshotsOutput {
    /// <p>An array of snapshots.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.snapshots.is_none()`.
    pub fn snapshots(&self) -> &[crate::types::Snapshot] {
        self.snapshots.as_deref().unwrap_or_default()
    }
    /// <p>(Optional) Opaque pagination token returned from a previous operation (String). If present, this token indicates from what point you can continue processing the request, where the previous <code>NextToken</code> value left off.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeSnapshotsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeSnapshotsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeSnapshotsOutput`](crate::operation::describe_snapshots::DescribeSnapshotsOutput).
    pub fn builder() -> crate::operation::describe_snapshots::builders::DescribeSnapshotsOutputBuilder {
        crate::operation::describe_snapshots::builders::DescribeSnapshotsOutputBuilder::default()
    }
}

/// A builder for [`DescribeSnapshotsOutput`](crate::operation::describe_snapshots::DescribeSnapshotsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSnapshotsOutputBuilder {
    pub(crate) snapshots: ::std::option::Option<::std::vec::Vec<crate::types::Snapshot>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeSnapshotsOutputBuilder {
    /// Appends an item to `snapshots`.
    ///
    /// To override the contents of this collection use [`set_snapshots`](Self::set_snapshots).
    ///
    /// <p>An array of snapshots.</p>
    pub fn snapshots(mut self, input: crate::types::Snapshot) -> Self {
        let mut v = self.snapshots.unwrap_or_default();
        v.push(input);
        self.snapshots = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of snapshots.</p>
    pub fn set_snapshots(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Snapshot>>) -> Self {
        self.snapshots = input;
        self
    }
    /// <p>An array of snapshots.</p>
    pub fn get_snapshots(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Snapshot>> {
        &self.snapshots
    }
    /// <p>(Optional) Opaque pagination token returned from a previous operation (String). If present, this token indicates from what point you can continue processing the request, where the previous <code>NextToken</code> value left off.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) Opaque pagination token returned from a previous operation (String). If present, this token indicates from what point you can continue processing the request, where the previous <code>NextToken</code> value left off.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>(Optional) Opaque pagination token returned from a previous operation (String). If present, this token indicates from what point you can continue processing the request, where the previous <code>NextToken</code> value left off.</p>
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
    /// Consumes the builder and constructs a [`DescribeSnapshotsOutput`](crate::operation::describe_snapshots::DescribeSnapshotsOutput).
    pub fn build(self) -> crate::operation::describe_snapshots::DescribeSnapshotsOutput {
        crate::operation::describe_snapshots::DescribeSnapshotsOutput {
            snapshots: self.snapshots,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
