// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A data structure with information about any primary and secondary clusters associated with a global cluster (Aurora global database).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GlobalClusterMember {
    /// <p>The Amazon Resource Name (ARN) for each Aurora DB cluster in the global cluster.</p>
    pub db_cluster_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for each read-only secondary cluster associated with the global cluster.</p>
    pub readers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Indicates whether the Aurora DB cluster is the primary cluster (that is, has read-write capability) for the global cluster with which it is associated.</p>
    pub is_writer: ::std::option::Option<bool>,
    /// <p>The status of write forwarding for a secondary cluster in the global cluster.</p>
    pub global_write_forwarding_status: ::std::option::Option<crate::types::WriteForwardingStatus>,
    /// <p>The status of synchronization of each Aurora DB cluster in the global cluster.</p>
    pub synchronization_status: ::std::option::Option<crate::types::GlobalClusterMemberSynchronizationStatus>,
}
impl GlobalClusterMember {
    /// <p>The Amazon Resource Name (ARN) for each Aurora DB cluster in the global cluster.</p>
    pub fn db_cluster_arn(&self) -> ::std::option::Option<&str> {
        self.db_cluster_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for each read-only secondary cluster associated with the global cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.readers.is_none()`.
    pub fn readers(&self) -> &[::std::string::String] {
        self.readers.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether the Aurora DB cluster is the primary cluster (that is, has read-write capability) for the global cluster with which it is associated.</p>
    pub fn is_writer(&self) -> ::std::option::Option<bool> {
        self.is_writer
    }
    /// <p>The status of write forwarding for a secondary cluster in the global cluster.</p>
    pub fn global_write_forwarding_status(&self) -> ::std::option::Option<&crate::types::WriteForwardingStatus> {
        self.global_write_forwarding_status.as_ref()
    }
    /// <p>The status of synchronization of each Aurora DB cluster in the global cluster.</p>
    pub fn synchronization_status(&self) -> ::std::option::Option<&crate::types::GlobalClusterMemberSynchronizationStatus> {
        self.synchronization_status.as_ref()
    }
}
impl GlobalClusterMember {
    /// Creates a new builder-style object to manufacture [`GlobalClusterMember`](crate::types::GlobalClusterMember).
    pub fn builder() -> crate::types::builders::GlobalClusterMemberBuilder {
        crate::types::builders::GlobalClusterMemberBuilder::default()
    }
}

/// A builder for [`GlobalClusterMember`](crate::types::GlobalClusterMember).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GlobalClusterMemberBuilder {
    pub(crate) db_cluster_arn: ::std::option::Option<::std::string::String>,
    pub(crate) readers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) is_writer: ::std::option::Option<bool>,
    pub(crate) global_write_forwarding_status: ::std::option::Option<crate::types::WriteForwardingStatus>,
    pub(crate) synchronization_status: ::std::option::Option<crate::types::GlobalClusterMemberSynchronizationStatus>,
}
impl GlobalClusterMemberBuilder {
    /// <p>The Amazon Resource Name (ARN) for each Aurora DB cluster in the global cluster.</p>
    pub fn db_cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for each Aurora DB cluster in the global cluster.</p>
    pub fn set_db_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_cluster_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for each Aurora DB cluster in the global cluster.</p>
    pub fn get_db_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_cluster_arn
    }
    /// Appends an item to `readers`.
    ///
    /// To override the contents of this collection use [`set_readers`](Self::set_readers).
    ///
    /// <p>The Amazon Resource Name (ARN) for each read-only secondary cluster associated with the global cluster.</p>
    pub fn readers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.readers.unwrap_or_default();
        v.push(input.into());
        self.readers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Name (ARN) for each read-only secondary cluster associated with the global cluster.</p>
    pub fn set_readers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.readers = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for each read-only secondary cluster associated with the global cluster.</p>
    pub fn get_readers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.readers
    }
    /// <p>Indicates whether the Aurora DB cluster is the primary cluster (that is, has read-write capability) for the global cluster with which it is associated.</p>
    pub fn is_writer(mut self, input: bool) -> Self {
        self.is_writer = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the Aurora DB cluster is the primary cluster (that is, has read-write capability) for the global cluster with which it is associated.</p>
    pub fn set_is_writer(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_writer = input;
        self
    }
    /// <p>Indicates whether the Aurora DB cluster is the primary cluster (that is, has read-write capability) for the global cluster with which it is associated.</p>
    pub fn get_is_writer(&self) -> &::std::option::Option<bool> {
        &self.is_writer
    }
    /// <p>The status of write forwarding for a secondary cluster in the global cluster.</p>
    pub fn global_write_forwarding_status(mut self, input: crate::types::WriteForwardingStatus) -> Self {
        self.global_write_forwarding_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of write forwarding for a secondary cluster in the global cluster.</p>
    pub fn set_global_write_forwarding_status(mut self, input: ::std::option::Option<crate::types::WriteForwardingStatus>) -> Self {
        self.global_write_forwarding_status = input;
        self
    }
    /// <p>The status of write forwarding for a secondary cluster in the global cluster.</p>
    pub fn get_global_write_forwarding_status(&self) -> &::std::option::Option<crate::types::WriteForwardingStatus> {
        &self.global_write_forwarding_status
    }
    /// <p>The status of synchronization of each Aurora DB cluster in the global cluster.</p>
    pub fn synchronization_status(mut self, input: crate::types::GlobalClusterMemberSynchronizationStatus) -> Self {
        self.synchronization_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of synchronization of each Aurora DB cluster in the global cluster.</p>
    pub fn set_synchronization_status(mut self, input: ::std::option::Option<crate::types::GlobalClusterMemberSynchronizationStatus>) -> Self {
        self.synchronization_status = input;
        self
    }
    /// <p>The status of synchronization of each Aurora DB cluster in the global cluster.</p>
    pub fn get_synchronization_status(&self) -> &::std::option::Option<crate::types::GlobalClusterMemberSynchronizationStatus> {
        &self.synchronization_status
    }
    /// Consumes the builder and constructs a [`GlobalClusterMember`](crate::types::GlobalClusterMember).
    pub fn build(self) -> crate::types::GlobalClusterMember {
        crate::types::GlobalClusterMember {
            db_cluster_arn: self.db_cluster_arn,
            readers: self.readers,
            is_writer: self.is_writer,
            global_write_forwarding_status: self.global_write_forwarding_status,
            synchronization_status: self.synchronization_status,
        }
    }
}
