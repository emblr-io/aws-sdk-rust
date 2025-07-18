// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSegmentSnapshotInput {
    /// <p>The unique identifier of the domain.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique name of the segment definition.</p>
    pub segment_definition_name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the segment snapshot.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
}
impl GetSegmentSnapshotInput {
    /// <p>The unique identifier of the domain.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
    /// <p>The unique name of the segment definition.</p>
    pub fn segment_definition_name(&self) -> ::std::option::Option<&str> {
        self.segment_definition_name.as_deref()
    }
    /// <p>The unique identifier of the segment snapshot.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
}
impl GetSegmentSnapshotInput {
    /// Creates a new builder-style object to manufacture [`GetSegmentSnapshotInput`](crate::operation::get_segment_snapshot::GetSegmentSnapshotInput).
    pub fn builder() -> crate::operation::get_segment_snapshot::builders::GetSegmentSnapshotInputBuilder {
        crate::operation::get_segment_snapshot::builders::GetSegmentSnapshotInputBuilder::default()
    }
}

/// A builder for [`GetSegmentSnapshotInput`](crate::operation::get_segment_snapshot::GetSegmentSnapshotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSegmentSnapshotInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
    pub(crate) segment_definition_name: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
}
impl GetSegmentSnapshotInputBuilder {
    /// <p>The unique identifier of the domain.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the domain.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The unique identifier of the domain.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// <p>The unique name of the segment definition.</p>
    /// This field is required.
    pub fn segment_definition_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.segment_definition_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the segment definition.</p>
    pub fn set_segment_definition_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.segment_definition_name = input;
        self
    }
    /// <p>The unique name of the segment definition.</p>
    pub fn get_segment_definition_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.segment_definition_name
    }
    /// <p>The unique identifier of the segment snapshot.</p>
    /// This field is required.
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the segment snapshot.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>The unique identifier of the segment snapshot.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    /// Consumes the builder and constructs a [`GetSegmentSnapshotInput`](crate::operation::get_segment_snapshot::GetSegmentSnapshotInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_segment_snapshot::GetSegmentSnapshotInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_segment_snapshot::GetSegmentSnapshotInput {
            domain_name: self.domain_name,
            segment_definition_name: self.segment_definition_name,
            snapshot_id: self.snapshot_id,
        })
    }
}
