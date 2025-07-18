// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopySnapshotAndUpdateVolumeInput {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the ID of the volume that you are copying the snapshot to.</p>
    pub volume_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) for a given resource. ARNs uniquely identify Amazon Web Services resources. We require an ARN when you need to specify a resource unambiguously across all of Amazon Web Services. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub source_snapshot_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the strategy to use when copying data from a snapshot to the volume.</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_COPY</code> - Copies all data from the snapshot to the volume.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_COPY</code> - Copies only the snapshot data that's changed since the previous replication.</p></li>
    /// </ul><note>
    /// <p><code>CLONE</code> isn't a valid copy strategy option for the <code>CopySnapshotAndUpdateVolume</code> operation.</p>
    /// </note>
    pub copy_strategy: ::std::option::Option<crate::types::OpenZfsCopyStrategy>,
    /// <p>Confirms that you want to delete data on the destination volume that wasn’t there during the previous snapshot replication.</p>
    /// <p>Your replication will fail if you don’t include an option for a specific type of data and that data is on your destination. For example, if you don’t include <code>DELETE_INTERMEDIATE_SNAPSHOTS</code> and there are intermediate snapshots on the destination, you can’t copy the snapshot.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_SNAPSHOTS</code> - Deletes snapshots on the destination volume that aren’t on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_CLONED_VOLUMES</code> - Deletes snapshot clones on the destination volume that aren't on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_DATA</code> - Overwrites snapshots on the destination volume that don’t match the source snapshot that you’re copying.</p></li>
    /// </ul>
    pub options: ::std::option::Option<::std::vec::Vec<crate::types::UpdateOpenZfsVolumeOption>>,
}
impl CopySnapshotAndUpdateVolumeInput {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>Specifies the ID of the volume that you are copying the snapshot to.</p>
    pub fn volume_id(&self) -> ::std::option::Option<&str> {
        self.volume_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) for a given resource. ARNs uniquely identify Amazon Web Services resources. We require an ARN when you need to specify a resource unambiguously across all of Amazon Web Services. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn source_snapshot_arn(&self) -> ::std::option::Option<&str> {
        self.source_snapshot_arn.as_deref()
    }
    /// <p>Specifies the strategy to use when copying data from a snapshot to the volume.</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_COPY</code> - Copies all data from the snapshot to the volume.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_COPY</code> - Copies only the snapshot data that's changed since the previous replication.</p></li>
    /// </ul><note>
    /// <p><code>CLONE</code> isn't a valid copy strategy option for the <code>CopySnapshotAndUpdateVolume</code> operation.</p>
    /// </note>
    pub fn copy_strategy(&self) -> ::std::option::Option<&crate::types::OpenZfsCopyStrategy> {
        self.copy_strategy.as_ref()
    }
    /// <p>Confirms that you want to delete data on the destination volume that wasn’t there during the previous snapshot replication.</p>
    /// <p>Your replication will fail if you don’t include an option for a specific type of data and that data is on your destination. For example, if you don’t include <code>DELETE_INTERMEDIATE_SNAPSHOTS</code> and there are intermediate snapshots on the destination, you can’t copy the snapshot.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_SNAPSHOTS</code> - Deletes snapshots on the destination volume that aren’t on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_CLONED_VOLUMES</code> - Deletes snapshot clones on the destination volume that aren't on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_DATA</code> - Overwrites snapshots on the destination volume that don’t match the source snapshot that you’re copying.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.options.is_none()`.
    pub fn options(&self) -> &[crate::types::UpdateOpenZfsVolumeOption] {
        self.options.as_deref().unwrap_or_default()
    }
}
impl CopySnapshotAndUpdateVolumeInput {
    /// Creates a new builder-style object to manufacture [`CopySnapshotAndUpdateVolumeInput`](crate::operation::copy_snapshot_and_update_volume::CopySnapshotAndUpdateVolumeInput).
    pub fn builder() -> crate::operation::copy_snapshot_and_update_volume::builders::CopySnapshotAndUpdateVolumeInputBuilder {
        crate::operation::copy_snapshot_and_update_volume::builders::CopySnapshotAndUpdateVolumeInputBuilder::default()
    }
}

/// A builder for [`CopySnapshotAndUpdateVolumeInput`](crate::operation::copy_snapshot_and_update_volume::CopySnapshotAndUpdateVolumeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopySnapshotAndUpdateVolumeInputBuilder {
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) volume_id: ::std::option::Option<::std::string::String>,
    pub(crate) source_snapshot_arn: ::std::option::Option<::std::string::String>,
    pub(crate) copy_strategy: ::std::option::Option<crate::types::OpenZfsCopyStrategy>,
    pub(crate) options: ::std::option::Option<::std::vec::Vec<crate::types::UpdateOpenZfsVolumeOption>>,
}
impl CopySnapshotAndUpdateVolumeInputBuilder {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>Specifies the ID of the volume that you are copying the snapshot to.</p>
    /// This field is required.
    pub fn volume_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the ID of the volume that you are copying the snapshot to.</p>
    pub fn set_volume_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_id = input;
        self
    }
    /// <p>Specifies the ID of the volume that you are copying the snapshot to.</p>
    pub fn get_volume_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_id
    }
    /// <p>The Amazon Resource Name (ARN) for a given resource. ARNs uniquely identify Amazon Web Services resources. We require an ARN when you need to specify a resource unambiguously across all of Amazon Web Services. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    /// This field is required.
    pub fn source_snapshot_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_snapshot_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for a given resource. ARNs uniquely identify Amazon Web Services resources. We require an ARN when you need to specify a resource unambiguously across all of Amazon Web Services. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_source_snapshot_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_snapshot_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for a given resource. ARNs uniquely identify Amazon Web Services resources. We require an ARN when you need to specify a resource unambiguously across all of Amazon Web Services. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_source_snapshot_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_snapshot_arn
    }
    /// <p>Specifies the strategy to use when copying data from a snapshot to the volume.</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_COPY</code> - Copies all data from the snapshot to the volume.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_COPY</code> - Copies only the snapshot data that's changed since the previous replication.</p></li>
    /// </ul><note>
    /// <p><code>CLONE</code> isn't a valid copy strategy option for the <code>CopySnapshotAndUpdateVolume</code> operation.</p>
    /// </note>
    pub fn copy_strategy(mut self, input: crate::types::OpenZfsCopyStrategy) -> Self {
        self.copy_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the strategy to use when copying data from a snapshot to the volume.</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_COPY</code> - Copies all data from the snapshot to the volume.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_COPY</code> - Copies only the snapshot data that's changed since the previous replication.</p></li>
    /// </ul><note>
    /// <p><code>CLONE</code> isn't a valid copy strategy option for the <code>CopySnapshotAndUpdateVolume</code> operation.</p>
    /// </note>
    pub fn set_copy_strategy(mut self, input: ::std::option::Option<crate::types::OpenZfsCopyStrategy>) -> Self {
        self.copy_strategy = input;
        self
    }
    /// <p>Specifies the strategy to use when copying data from a snapshot to the volume.</p>
    /// <ul>
    /// <li>
    /// <p><code>FULL_COPY</code> - Copies all data from the snapshot to the volume.</p></li>
    /// <li>
    /// <p><code>INCREMENTAL_COPY</code> - Copies only the snapshot data that's changed since the previous replication.</p></li>
    /// </ul><note>
    /// <p><code>CLONE</code> isn't a valid copy strategy option for the <code>CopySnapshotAndUpdateVolume</code> operation.</p>
    /// </note>
    pub fn get_copy_strategy(&self) -> &::std::option::Option<crate::types::OpenZfsCopyStrategy> {
        &self.copy_strategy
    }
    /// Appends an item to `options`.
    ///
    /// To override the contents of this collection use [`set_options`](Self::set_options).
    ///
    /// <p>Confirms that you want to delete data on the destination volume that wasn’t there during the previous snapshot replication.</p>
    /// <p>Your replication will fail if you don’t include an option for a specific type of data and that data is on your destination. For example, if you don’t include <code>DELETE_INTERMEDIATE_SNAPSHOTS</code> and there are intermediate snapshots on the destination, you can’t copy the snapshot.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_SNAPSHOTS</code> - Deletes snapshots on the destination volume that aren’t on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_CLONED_VOLUMES</code> - Deletes snapshot clones on the destination volume that aren't on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_DATA</code> - Overwrites snapshots on the destination volume that don’t match the source snapshot that you’re copying.</p></li>
    /// </ul>
    pub fn options(mut self, input: crate::types::UpdateOpenZfsVolumeOption) -> Self {
        let mut v = self.options.unwrap_or_default();
        v.push(input);
        self.options = ::std::option::Option::Some(v);
        self
    }
    /// <p>Confirms that you want to delete data on the destination volume that wasn’t there during the previous snapshot replication.</p>
    /// <p>Your replication will fail if you don’t include an option for a specific type of data and that data is on your destination. For example, if you don’t include <code>DELETE_INTERMEDIATE_SNAPSHOTS</code> and there are intermediate snapshots on the destination, you can’t copy the snapshot.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_SNAPSHOTS</code> - Deletes snapshots on the destination volume that aren’t on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_CLONED_VOLUMES</code> - Deletes snapshot clones on the destination volume that aren't on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_DATA</code> - Overwrites snapshots on the destination volume that don’t match the source snapshot that you’re copying.</p></li>
    /// </ul>
    pub fn set_options(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UpdateOpenZfsVolumeOption>>) -> Self {
        self.options = input;
        self
    }
    /// <p>Confirms that you want to delete data on the destination volume that wasn’t there during the previous snapshot replication.</p>
    /// <p>Your replication will fail if you don’t include an option for a specific type of data and that data is on your destination. For example, if you don’t include <code>DELETE_INTERMEDIATE_SNAPSHOTS</code> and there are intermediate snapshots on the destination, you can’t copy the snapshot.</p>
    /// <ul>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_SNAPSHOTS</code> - Deletes snapshots on the destination volume that aren’t on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_CLONED_VOLUMES</code> - Deletes snapshot clones on the destination volume that aren't on the source volume.</p></li>
    /// <li>
    /// <p><code>DELETE_INTERMEDIATE_DATA</code> - Overwrites snapshots on the destination volume that don’t match the source snapshot that you’re copying.</p></li>
    /// </ul>
    pub fn get_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UpdateOpenZfsVolumeOption>> {
        &self.options
    }
    /// Consumes the builder and constructs a [`CopySnapshotAndUpdateVolumeInput`](crate::operation::copy_snapshot_and_update_volume::CopySnapshotAndUpdateVolumeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::copy_snapshot_and_update_volume::CopySnapshotAndUpdateVolumeInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::copy_snapshot_and_update_volume::CopySnapshotAndUpdateVolumeInput {
            client_request_token: self.client_request_token,
            volume_id: self.volume_id,
            source_snapshot_arn: self.source_snapshot_arn,
            copy_strategy: self.copy_strategy,
            options: self.options,
        })
    }
}
