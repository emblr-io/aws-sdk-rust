// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCollectionOutput {
    /// <p>The number of faces that are indexed into the collection. To index faces into a collection, use <code>IndexFaces</code>.</p>
    pub face_count: ::std::option::Option<i64>,
    /// <p>The version of the face model that's used by the collection for face detection.</p>
    /// <p>For more information, see Model versioning in the Amazon Rekognition Developer Guide.</p>
    pub face_model_version: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the collection.</p>
    pub collection_arn: ::std::option::Option<::std::string::String>,
    /// <p>The number of milliseconds since the Unix epoch time until the creation of the collection. The Unix epoch time is 00:00:00 Coordinated Universal Time (UTC), Thursday, 1 January 1970.</p>
    pub creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The number of UserIDs assigned to the specified colleciton.</p>
    pub user_count: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl DescribeCollectionOutput {
    /// <p>The number of faces that are indexed into the collection. To index faces into a collection, use <code>IndexFaces</code>.</p>
    pub fn face_count(&self) -> ::std::option::Option<i64> {
        self.face_count
    }
    /// <p>The version of the face model that's used by the collection for face detection.</p>
    /// <p>For more information, see Model versioning in the Amazon Rekognition Developer Guide.</p>
    pub fn face_model_version(&self) -> ::std::option::Option<&str> {
        self.face_model_version.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the collection.</p>
    pub fn collection_arn(&self) -> ::std::option::Option<&str> {
        self.collection_arn.as_deref()
    }
    /// <p>The number of milliseconds since the Unix epoch time until the creation of the collection. The Unix epoch time is 00:00:00 Coordinated Universal Time (UTC), Thursday, 1 January 1970.</p>
    pub fn creation_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_timestamp.as_ref()
    }
    /// <p>The number of UserIDs assigned to the specified colleciton.</p>
    pub fn user_count(&self) -> ::std::option::Option<i64> {
        self.user_count
    }
}
impl ::aws_types::request_id::RequestId for DescribeCollectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCollectionOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCollectionOutput`](crate::operation::describe_collection::DescribeCollectionOutput).
    pub fn builder() -> crate::operation::describe_collection::builders::DescribeCollectionOutputBuilder {
        crate::operation::describe_collection::builders::DescribeCollectionOutputBuilder::default()
    }
}

/// A builder for [`DescribeCollectionOutput`](crate::operation::describe_collection::DescribeCollectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCollectionOutputBuilder {
    pub(crate) face_count: ::std::option::Option<i64>,
    pub(crate) face_model_version: ::std::option::Option<::std::string::String>,
    pub(crate) collection_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) user_count: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl DescribeCollectionOutputBuilder {
    /// <p>The number of faces that are indexed into the collection. To index faces into a collection, use <code>IndexFaces</code>.</p>
    pub fn face_count(mut self, input: i64) -> Self {
        self.face_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of faces that are indexed into the collection. To index faces into a collection, use <code>IndexFaces</code>.</p>
    pub fn set_face_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.face_count = input;
        self
    }
    /// <p>The number of faces that are indexed into the collection. To index faces into a collection, use <code>IndexFaces</code>.</p>
    pub fn get_face_count(&self) -> &::std::option::Option<i64> {
        &self.face_count
    }
    /// <p>The version of the face model that's used by the collection for face detection.</p>
    /// <p>For more information, see Model versioning in the Amazon Rekognition Developer Guide.</p>
    pub fn face_model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.face_model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the face model that's used by the collection for face detection.</p>
    /// <p>For more information, see Model versioning in the Amazon Rekognition Developer Guide.</p>
    pub fn set_face_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.face_model_version = input;
        self
    }
    /// <p>The version of the face model that's used by the collection for face detection.</p>
    /// <p>For more information, see Model versioning in the Amazon Rekognition Developer Guide.</p>
    pub fn get_face_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.face_model_version
    }
    /// <p>The Amazon Resource Name (ARN) of the collection.</p>
    pub fn collection_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collection_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the collection.</p>
    pub fn set_collection_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collection_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the collection.</p>
    pub fn get_collection_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.collection_arn
    }
    /// <p>The number of milliseconds since the Unix epoch time until the creation of the collection. The Unix epoch time is 00:00:00 Coordinated Universal Time (UTC), Thursday, 1 January 1970.</p>
    pub fn creation_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of milliseconds since the Unix epoch time until the creation of the collection. The Unix epoch time is 00:00:00 Coordinated Universal Time (UTC), Thursday, 1 January 1970.</p>
    pub fn set_creation_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_timestamp = input;
        self
    }
    /// <p>The number of milliseconds since the Unix epoch time until the creation of the collection. The Unix epoch time is 00:00:00 Coordinated Universal Time (UTC), Thursday, 1 January 1970.</p>
    pub fn get_creation_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_timestamp
    }
    /// <p>The number of UserIDs assigned to the specified colleciton.</p>
    pub fn user_count(mut self, input: i64) -> Self {
        self.user_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of UserIDs assigned to the specified colleciton.</p>
    pub fn set_user_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.user_count = input;
        self
    }
    /// <p>The number of UserIDs assigned to the specified colleciton.</p>
    pub fn get_user_count(&self) -> &::std::option::Option<i64> {
        &self.user_count
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCollectionOutput`](crate::operation::describe_collection::DescribeCollectionOutput).
    pub fn build(self) -> crate::operation::describe_collection::DescribeCollectionOutput {
        crate::operation::describe_collection::DescribeCollectionOutput {
            face_count: self.face_count,
            face_model_version: self.face_model_version,
            collection_arn: self.collection_arn,
            creation_timestamp: self.creation_timestamp,
            user_count: self.user_count,
            _request_id: self._request_id,
        }
    }
}
