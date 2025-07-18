// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRecordInput {
    /// <p>The name or Amazon Resource Name (ARN) of the feature group that you want to insert the record into.</p>
    pub feature_group_name: ::std::option::Option<::std::string::String>,
    /// <p>List of FeatureValues to be inserted. This will be a full over-write. If you only want to update few of the feature values, do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>GetRecord</code> to retrieve the latest record.</p></li>
    /// <li>
    /// <p>Update the record returned from <code>GetRecord</code>.</p></li>
    /// <li>
    /// <p>Use <code>PutRecord</code> to update feature values.</p></li>
    /// </ul>
    pub record: ::std::option::Option<::std::vec::Vec<crate::types::FeatureValue>>,
    /// <p>A list of stores to which you're adding the record. By default, Feature Store adds the record to all of the stores that you're using for the <code>FeatureGroup</code>.</p>
    pub target_stores: ::std::option::Option<::std::vec::Vec<crate::types::TargetStore>>,
    /// <p>Time to live duration, where the record is hard deleted after the expiration time is reached; <code>ExpiresAt</code> = <code>EventTime</code> + <code>TtlDuration</code>. For information on HardDelete, see the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_feature_store_DeleteRecord.html">DeleteRecord</a> API in the Amazon SageMaker API Reference guide.</p>
    pub ttl_duration: ::std::option::Option<crate::types::TtlDuration>,
}
impl PutRecordInput {
    /// <p>The name or Amazon Resource Name (ARN) of the feature group that you want to insert the record into.</p>
    pub fn feature_group_name(&self) -> ::std::option::Option<&str> {
        self.feature_group_name.as_deref()
    }
    /// <p>List of FeatureValues to be inserted. This will be a full over-write. If you only want to update few of the feature values, do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>GetRecord</code> to retrieve the latest record.</p></li>
    /// <li>
    /// <p>Update the record returned from <code>GetRecord</code>.</p></li>
    /// <li>
    /// <p>Use <code>PutRecord</code> to update feature values.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.record.is_none()`.
    pub fn record(&self) -> &[crate::types::FeatureValue] {
        self.record.as_deref().unwrap_or_default()
    }
    /// <p>A list of stores to which you're adding the record. By default, Feature Store adds the record to all of the stores that you're using for the <code>FeatureGroup</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_stores.is_none()`.
    pub fn target_stores(&self) -> &[crate::types::TargetStore] {
        self.target_stores.as_deref().unwrap_or_default()
    }
    /// <p>Time to live duration, where the record is hard deleted after the expiration time is reached; <code>ExpiresAt</code> = <code>EventTime</code> + <code>TtlDuration</code>. For information on HardDelete, see the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_feature_store_DeleteRecord.html">DeleteRecord</a> API in the Amazon SageMaker API Reference guide.</p>
    pub fn ttl_duration(&self) -> ::std::option::Option<&crate::types::TtlDuration> {
        self.ttl_duration.as_ref()
    }
}
impl PutRecordInput {
    /// Creates a new builder-style object to manufacture [`PutRecordInput`](crate::operation::put_record::PutRecordInput).
    pub fn builder() -> crate::operation::put_record::builders::PutRecordInputBuilder {
        crate::operation::put_record::builders::PutRecordInputBuilder::default()
    }
}

/// A builder for [`PutRecordInput`](crate::operation::put_record::PutRecordInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRecordInputBuilder {
    pub(crate) feature_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) record: ::std::option::Option<::std::vec::Vec<crate::types::FeatureValue>>,
    pub(crate) target_stores: ::std::option::Option<::std::vec::Vec<crate::types::TargetStore>>,
    pub(crate) ttl_duration: ::std::option::Option<crate::types::TtlDuration>,
}
impl PutRecordInputBuilder {
    /// <p>The name or Amazon Resource Name (ARN) of the feature group that you want to insert the record into.</p>
    /// This field is required.
    pub fn feature_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feature_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the feature group that you want to insert the record into.</p>
    pub fn set_feature_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feature_group_name = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the feature group that you want to insert the record into.</p>
    pub fn get_feature_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.feature_group_name
    }
    /// Appends an item to `record`.
    ///
    /// To override the contents of this collection use [`set_record`](Self::set_record).
    ///
    /// <p>List of FeatureValues to be inserted. This will be a full over-write. If you only want to update few of the feature values, do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>GetRecord</code> to retrieve the latest record.</p></li>
    /// <li>
    /// <p>Update the record returned from <code>GetRecord</code>.</p></li>
    /// <li>
    /// <p>Use <code>PutRecord</code> to update feature values.</p></li>
    /// </ul>
    pub fn record(mut self, input: crate::types::FeatureValue) -> Self {
        let mut v = self.record.unwrap_or_default();
        v.push(input);
        self.record = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of FeatureValues to be inserted. This will be a full over-write. If you only want to update few of the feature values, do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>GetRecord</code> to retrieve the latest record.</p></li>
    /// <li>
    /// <p>Update the record returned from <code>GetRecord</code>.</p></li>
    /// <li>
    /// <p>Use <code>PutRecord</code> to update feature values.</p></li>
    /// </ul>
    pub fn set_record(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FeatureValue>>) -> Self {
        self.record = input;
        self
    }
    /// <p>List of FeatureValues to be inserted. This will be a full over-write. If you only want to update few of the feature values, do the following:</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>GetRecord</code> to retrieve the latest record.</p></li>
    /// <li>
    /// <p>Update the record returned from <code>GetRecord</code>.</p></li>
    /// <li>
    /// <p>Use <code>PutRecord</code> to update feature values.</p></li>
    /// </ul>
    pub fn get_record(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FeatureValue>> {
        &self.record
    }
    /// Appends an item to `target_stores`.
    ///
    /// To override the contents of this collection use [`set_target_stores`](Self::set_target_stores).
    ///
    /// <p>A list of stores to which you're adding the record. By default, Feature Store adds the record to all of the stores that you're using for the <code>FeatureGroup</code>.</p>
    pub fn target_stores(mut self, input: crate::types::TargetStore) -> Self {
        let mut v = self.target_stores.unwrap_or_default();
        v.push(input);
        self.target_stores = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of stores to which you're adding the record. By default, Feature Store adds the record to all of the stores that you're using for the <code>FeatureGroup</code>.</p>
    pub fn set_target_stores(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TargetStore>>) -> Self {
        self.target_stores = input;
        self
    }
    /// <p>A list of stores to which you're adding the record. By default, Feature Store adds the record to all of the stores that you're using for the <code>FeatureGroup</code>.</p>
    pub fn get_target_stores(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TargetStore>> {
        &self.target_stores
    }
    /// <p>Time to live duration, where the record is hard deleted after the expiration time is reached; <code>ExpiresAt</code> = <code>EventTime</code> + <code>TtlDuration</code>. For information on HardDelete, see the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_feature_store_DeleteRecord.html">DeleteRecord</a> API in the Amazon SageMaker API Reference guide.</p>
    pub fn ttl_duration(mut self, input: crate::types::TtlDuration) -> Self {
        self.ttl_duration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Time to live duration, where the record is hard deleted after the expiration time is reached; <code>ExpiresAt</code> = <code>EventTime</code> + <code>TtlDuration</code>. For information on HardDelete, see the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_feature_store_DeleteRecord.html">DeleteRecord</a> API in the Amazon SageMaker API Reference guide.</p>
    pub fn set_ttl_duration(mut self, input: ::std::option::Option<crate::types::TtlDuration>) -> Self {
        self.ttl_duration = input;
        self
    }
    /// <p>Time to live duration, where the record is hard deleted after the expiration time is reached; <code>ExpiresAt</code> = <code>EventTime</code> + <code>TtlDuration</code>. For information on HardDelete, see the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_feature_store_DeleteRecord.html">DeleteRecord</a> API in the Amazon SageMaker API Reference guide.</p>
    pub fn get_ttl_duration(&self) -> &::std::option::Option<crate::types::TtlDuration> {
        &self.ttl_duration
    }
    /// Consumes the builder and constructs a [`PutRecordInput`](crate::operation::put_record::PutRecordInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::put_record::PutRecordInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_record::PutRecordInput {
            feature_group_name: self.feature_group_name,
            record: self.record,
            target_stores: self.target_stores,
            ttl_duration: self.ttl_duration,
        })
    }
}
