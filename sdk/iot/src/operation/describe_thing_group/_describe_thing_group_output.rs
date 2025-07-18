// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeThingGroupOutput {
    /// <p>The name of the thing group.</p>
    pub thing_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The thing group ID.</p>
    pub thing_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The thing group ARN.</p>
    pub thing_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The version of the thing group.</p>
    pub version: i64,
    /// <p>The thing group properties.</p>
    pub thing_group_properties: ::std::option::Option<crate::types::ThingGroupProperties>,
    /// <p>Thing group metadata.</p>
    pub thing_group_metadata: ::std::option::Option<crate::types::ThingGroupMetadata>,
    /// <p>The dynamic thing group index name.</p>
    pub index_name: ::std::option::Option<::std::string::String>,
    /// <p>The dynamic thing group search query string.</p>
    pub query_string: ::std::option::Option<::std::string::String>,
    /// <p>The dynamic thing group query version.</p>
    pub query_version: ::std::option::Option<::std::string::String>,
    /// <p>The dynamic thing group status.</p>
    pub status: ::std::option::Option<crate::types::DynamicGroupStatus>,
    _request_id: Option<String>,
}
impl DescribeThingGroupOutput {
    /// <p>The name of the thing group.</p>
    pub fn thing_group_name(&self) -> ::std::option::Option<&str> {
        self.thing_group_name.as_deref()
    }
    /// <p>The thing group ID.</p>
    pub fn thing_group_id(&self) -> ::std::option::Option<&str> {
        self.thing_group_id.as_deref()
    }
    /// <p>The thing group ARN.</p>
    pub fn thing_group_arn(&self) -> ::std::option::Option<&str> {
        self.thing_group_arn.as_deref()
    }
    /// <p>The version of the thing group.</p>
    pub fn version(&self) -> i64 {
        self.version
    }
    /// <p>The thing group properties.</p>
    pub fn thing_group_properties(&self) -> ::std::option::Option<&crate::types::ThingGroupProperties> {
        self.thing_group_properties.as_ref()
    }
    /// <p>Thing group metadata.</p>
    pub fn thing_group_metadata(&self) -> ::std::option::Option<&crate::types::ThingGroupMetadata> {
        self.thing_group_metadata.as_ref()
    }
    /// <p>The dynamic thing group index name.</p>
    pub fn index_name(&self) -> ::std::option::Option<&str> {
        self.index_name.as_deref()
    }
    /// <p>The dynamic thing group search query string.</p>
    pub fn query_string(&self) -> ::std::option::Option<&str> {
        self.query_string.as_deref()
    }
    /// <p>The dynamic thing group query version.</p>
    pub fn query_version(&self) -> ::std::option::Option<&str> {
        self.query_version.as_deref()
    }
    /// <p>The dynamic thing group status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DynamicGroupStatus> {
        self.status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeThingGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeThingGroupOutput {
    /// Creates a new builder-style object to manufacture [`DescribeThingGroupOutput`](crate::operation::describe_thing_group::DescribeThingGroupOutput).
    pub fn builder() -> crate::operation::describe_thing_group::builders::DescribeThingGroupOutputBuilder {
        crate::operation::describe_thing_group::builders::DescribeThingGroupOutputBuilder::default()
    }
}

/// A builder for [`DescribeThingGroupOutput`](crate::operation::describe_thing_group::DescribeThingGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeThingGroupOutputBuilder {
    pub(crate) thing_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) thing_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) thing_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<i64>,
    pub(crate) thing_group_properties: ::std::option::Option<crate::types::ThingGroupProperties>,
    pub(crate) thing_group_metadata: ::std::option::Option<crate::types::ThingGroupMetadata>,
    pub(crate) index_name: ::std::option::Option<::std::string::String>,
    pub(crate) query_string: ::std::option::Option<::std::string::String>,
    pub(crate) query_version: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DynamicGroupStatus>,
    _request_id: Option<String>,
}
impl DescribeThingGroupOutputBuilder {
    /// <p>The name of the thing group.</p>
    pub fn thing_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the thing group.</p>
    pub fn set_thing_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_group_name = input;
        self
    }
    /// <p>The name of the thing group.</p>
    pub fn get_thing_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_group_name
    }
    /// <p>The thing group ID.</p>
    pub fn thing_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The thing group ID.</p>
    pub fn set_thing_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_group_id = input;
        self
    }
    /// <p>The thing group ID.</p>
    pub fn get_thing_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_group_id
    }
    /// <p>The thing group ARN.</p>
    pub fn thing_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The thing group ARN.</p>
    pub fn set_thing_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_group_arn = input;
        self
    }
    /// <p>The thing group ARN.</p>
    pub fn get_thing_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_group_arn
    }
    /// <p>The version of the thing group.</p>
    pub fn version(mut self, input: i64) -> Self {
        self.version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the thing group.</p>
    pub fn set_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the thing group.</p>
    pub fn get_version(&self) -> &::std::option::Option<i64> {
        &self.version
    }
    /// <p>The thing group properties.</p>
    pub fn thing_group_properties(mut self, input: crate::types::ThingGroupProperties) -> Self {
        self.thing_group_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>The thing group properties.</p>
    pub fn set_thing_group_properties(mut self, input: ::std::option::Option<crate::types::ThingGroupProperties>) -> Self {
        self.thing_group_properties = input;
        self
    }
    /// <p>The thing group properties.</p>
    pub fn get_thing_group_properties(&self) -> &::std::option::Option<crate::types::ThingGroupProperties> {
        &self.thing_group_properties
    }
    /// <p>Thing group metadata.</p>
    pub fn thing_group_metadata(mut self, input: crate::types::ThingGroupMetadata) -> Self {
        self.thing_group_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>Thing group metadata.</p>
    pub fn set_thing_group_metadata(mut self, input: ::std::option::Option<crate::types::ThingGroupMetadata>) -> Self {
        self.thing_group_metadata = input;
        self
    }
    /// <p>Thing group metadata.</p>
    pub fn get_thing_group_metadata(&self) -> &::std::option::Option<crate::types::ThingGroupMetadata> {
        &self.thing_group_metadata
    }
    /// <p>The dynamic thing group index name.</p>
    pub fn index_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The dynamic thing group index name.</p>
    pub fn set_index_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_name = input;
        self
    }
    /// <p>The dynamic thing group index name.</p>
    pub fn get_index_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_name
    }
    /// <p>The dynamic thing group search query string.</p>
    pub fn query_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The dynamic thing group search query string.</p>
    pub fn set_query_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_string = input;
        self
    }
    /// <p>The dynamic thing group search query string.</p>
    pub fn get_query_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_string
    }
    /// <p>The dynamic thing group query version.</p>
    pub fn query_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The dynamic thing group query version.</p>
    pub fn set_query_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query_version = input;
        self
    }
    /// <p>The dynamic thing group query version.</p>
    pub fn get_query_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.query_version
    }
    /// <p>The dynamic thing group status.</p>
    pub fn status(mut self, input: crate::types::DynamicGroupStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dynamic thing group status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DynamicGroupStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The dynamic thing group status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DynamicGroupStatus> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeThingGroupOutput`](crate::operation::describe_thing_group::DescribeThingGroupOutput).
    pub fn build(self) -> crate::operation::describe_thing_group::DescribeThingGroupOutput {
        crate::operation::describe_thing_group::DescribeThingGroupOutput {
            thing_group_name: self.thing_group_name,
            thing_group_id: self.thing_group_id,
            thing_group_arn: self.thing_group_arn,
            version: self.version.unwrap_or_default(),
            thing_group_properties: self.thing_group_properties,
            thing_group_metadata: self.thing_group_metadata,
            index_name: self.index_name,
            query_string: self.query_string,
            query_version: self.query_version,
            status: self.status,
            _request_id: self._request_id,
        }
    }
}
