// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies configuration for replication between a source and target Kafka cluster (sourceKafkaClusterAlias -&gt; targetKafkaClusterAlias)</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReplicationInfoDescription {
    /// <p>Configuration relating to consumer group replication.</p>
    pub consumer_group_replication: ::std::option::Option<crate::types::ConsumerGroupReplication>,
    /// <p>The alias of the source Kafka cluster.</p>
    pub source_kafka_cluster_alias: ::std::option::Option<::std::string::String>,
    /// <p>The compression type to use when producing records to target cluster.</p>
    pub target_compression_type: ::std::option::Option<crate::types::TargetCompressionType>,
    /// <p>The alias of the target Kafka cluster.</p>
    pub target_kafka_cluster_alias: ::std::option::Option<::std::string::String>,
    /// <p>Configuration relating to topic replication.</p>
    pub topic_replication: ::std::option::Option<crate::types::TopicReplication>,
}
impl ReplicationInfoDescription {
    /// <p>Configuration relating to consumer group replication.</p>
    pub fn consumer_group_replication(&self) -> ::std::option::Option<&crate::types::ConsumerGroupReplication> {
        self.consumer_group_replication.as_ref()
    }
    /// <p>The alias of the source Kafka cluster.</p>
    pub fn source_kafka_cluster_alias(&self) -> ::std::option::Option<&str> {
        self.source_kafka_cluster_alias.as_deref()
    }
    /// <p>The compression type to use when producing records to target cluster.</p>
    pub fn target_compression_type(&self) -> ::std::option::Option<&crate::types::TargetCompressionType> {
        self.target_compression_type.as_ref()
    }
    /// <p>The alias of the target Kafka cluster.</p>
    pub fn target_kafka_cluster_alias(&self) -> ::std::option::Option<&str> {
        self.target_kafka_cluster_alias.as_deref()
    }
    /// <p>Configuration relating to topic replication.</p>
    pub fn topic_replication(&self) -> ::std::option::Option<&crate::types::TopicReplication> {
        self.topic_replication.as_ref()
    }
}
impl ReplicationInfoDescription {
    /// Creates a new builder-style object to manufacture [`ReplicationInfoDescription`](crate::types::ReplicationInfoDescription).
    pub fn builder() -> crate::types::builders::ReplicationInfoDescriptionBuilder {
        crate::types::builders::ReplicationInfoDescriptionBuilder::default()
    }
}

/// A builder for [`ReplicationInfoDescription`](crate::types::ReplicationInfoDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReplicationInfoDescriptionBuilder {
    pub(crate) consumer_group_replication: ::std::option::Option<crate::types::ConsumerGroupReplication>,
    pub(crate) source_kafka_cluster_alias: ::std::option::Option<::std::string::String>,
    pub(crate) target_compression_type: ::std::option::Option<crate::types::TargetCompressionType>,
    pub(crate) target_kafka_cluster_alias: ::std::option::Option<::std::string::String>,
    pub(crate) topic_replication: ::std::option::Option<crate::types::TopicReplication>,
}
impl ReplicationInfoDescriptionBuilder {
    /// <p>Configuration relating to consumer group replication.</p>
    pub fn consumer_group_replication(mut self, input: crate::types::ConsumerGroupReplication) -> Self {
        self.consumer_group_replication = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration relating to consumer group replication.</p>
    pub fn set_consumer_group_replication(mut self, input: ::std::option::Option<crate::types::ConsumerGroupReplication>) -> Self {
        self.consumer_group_replication = input;
        self
    }
    /// <p>Configuration relating to consumer group replication.</p>
    pub fn get_consumer_group_replication(&self) -> &::std::option::Option<crate::types::ConsumerGroupReplication> {
        &self.consumer_group_replication
    }
    /// <p>The alias of the source Kafka cluster.</p>
    pub fn source_kafka_cluster_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_kafka_cluster_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the source Kafka cluster.</p>
    pub fn set_source_kafka_cluster_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_kafka_cluster_alias = input;
        self
    }
    /// <p>The alias of the source Kafka cluster.</p>
    pub fn get_source_kafka_cluster_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_kafka_cluster_alias
    }
    /// <p>The compression type to use when producing records to target cluster.</p>
    pub fn target_compression_type(mut self, input: crate::types::TargetCompressionType) -> Self {
        self.target_compression_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compression type to use when producing records to target cluster.</p>
    pub fn set_target_compression_type(mut self, input: ::std::option::Option<crate::types::TargetCompressionType>) -> Self {
        self.target_compression_type = input;
        self
    }
    /// <p>The compression type to use when producing records to target cluster.</p>
    pub fn get_target_compression_type(&self) -> &::std::option::Option<crate::types::TargetCompressionType> {
        &self.target_compression_type
    }
    /// <p>The alias of the target Kafka cluster.</p>
    pub fn target_kafka_cluster_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_kafka_cluster_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias of the target Kafka cluster.</p>
    pub fn set_target_kafka_cluster_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_kafka_cluster_alias = input;
        self
    }
    /// <p>The alias of the target Kafka cluster.</p>
    pub fn get_target_kafka_cluster_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_kafka_cluster_alias
    }
    /// <p>Configuration relating to topic replication.</p>
    pub fn topic_replication(mut self, input: crate::types::TopicReplication) -> Self {
        self.topic_replication = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration relating to topic replication.</p>
    pub fn set_topic_replication(mut self, input: ::std::option::Option<crate::types::TopicReplication>) -> Self {
        self.topic_replication = input;
        self
    }
    /// <p>Configuration relating to topic replication.</p>
    pub fn get_topic_replication(&self) -> &::std::option::Option<crate::types::TopicReplication> {
        &self.topic_replication
    }
    /// Consumes the builder and constructs a [`ReplicationInfoDescription`](crate::types::ReplicationInfoDescription).
    pub fn build(self) -> crate::types::ReplicationInfoDescription {
        crate::types::ReplicationInfoDescription {
            consumer_group_replication: self.consumer_group_replication,
            source_kafka_cluster_alias: self.source_kafka_cluster_alias,
            target_compression_type: self.target_compression_type,
            target_kafka_cluster_alias: self.target_kafka_cluster_alias,
            topic_replication: self.topic_replication,
        }
    }
}
