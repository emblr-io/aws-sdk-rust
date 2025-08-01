// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes updates to the checkpointing parameters for a Managed Service for Apache Flink application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CheckpointConfigurationUpdate {
    /// <p>Describes updates to whether the application uses the default checkpointing behavior of Managed Service for Apache Flink. You must set this property to <code>CUSTOM</code> in order to set the <code>CheckpointingEnabled</code>, <code>CheckpointInterval</code>, or <code>MinPauseBetweenCheckpoints</code> parameters.</p><note>
    /// <p>If this value is set to <code>DEFAULT</code>, the application will use the following values, even if they are set to other values using APIs or application code:</p>
    /// <ul>
    /// <li>
    /// <p><b>CheckpointingEnabled:</b> true</p></li>
    /// <li>
    /// <p><b>CheckpointInterval:</b> 60000</p></li>
    /// <li>
    /// <p><b>MinPauseBetweenCheckpoints:</b> 5000</p></li>
    /// </ul>
    /// </note>
    pub configuration_type_update: ::std::option::Option<crate::types::ConfigurationType>,
    /// <p>Describes updates to whether checkpointing is enabled for an application.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointingEnabled</code> value of <code>true</code>, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub checkpointing_enabled_update: ::std::option::Option<bool>,
    /// <p>Describes updates to the interval in milliseconds between checkpoint operations.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointInterval</code> value of 60000, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub checkpoint_interval_update: ::std::option::Option<i64>,
    /// <p>Describes updates to the minimum time in milliseconds after a checkpoint operation completes that a new checkpoint operation can start.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>MinPauseBetweenCheckpoints</code> value of 5000, even if this value is set using this API or in application code.</p>
    /// </note>
    pub min_pause_between_checkpoints_update: ::std::option::Option<i64>,
}
impl CheckpointConfigurationUpdate {
    /// <p>Describes updates to whether the application uses the default checkpointing behavior of Managed Service for Apache Flink. You must set this property to <code>CUSTOM</code> in order to set the <code>CheckpointingEnabled</code>, <code>CheckpointInterval</code>, or <code>MinPauseBetweenCheckpoints</code> parameters.</p><note>
    /// <p>If this value is set to <code>DEFAULT</code>, the application will use the following values, even if they are set to other values using APIs or application code:</p>
    /// <ul>
    /// <li>
    /// <p><b>CheckpointingEnabled:</b> true</p></li>
    /// <li>
    /// <p><b>CheckpointInterval:</b> 60000</p></li>
    /// <li>
    /// <p><b>MinPauseBetweenCheckpoints:</b> 5000</p></li>
    /// </ul>
    /// </note>
    pub fn configuration_type_update(&self) -> ::std::option::Option<&crate::types::ConfigurationType> {
        self.configuration_type_update.as_ref()
    }
    /// <p>Describes updates to whether checkpointing is enabled for an application.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointingEnabled</code> value of <code>true</code>, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn checkpointing_enabled_update(&self) -> ::std::option::Option<bool> {
        self.checkpointing_enabled_update
    }
    /// <p>Describes updates to the interval in milliseconds between checkpoint operations.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointInterval</code> value of 60000, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn checkpoint_interval_update(&self) -> ::std::option::Option<i64> {
        self.checkpoint_interval_update
    }
    /// <p>Describes updates to the minimum time in milliseconds after a checkpoint operation completes that a new checkpoint operation can start.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>MinPauseBetweenCheckpoints</code> value of 5000, even if this value is set using this API or in application code.</p>
    /// </note>
    pub fn min_pause_between_checkpoints_update(&self) -> ::std::option::Option<i64> {
        self.min_pause_between_checkpoints_update
    }
}
impl CheckpointConfigurationUpdate {
    /// Creates a new builder-style object to manufacture [`CheckpointConfigurationUpdate`](crate::types::CheckpointConfigurationUpdate).
    pub fn builder() -> crate::types::builders::CheckpointConfigurationUpdateBuilder {
        crate::types::builders::CheckpointConfigurationUpdateBuilder::default()
    }
}

/// A builder for [`CheckpointConfigurationUpdate`](crate::types::CheckpointConfigurationUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CheckpointConfigurationUpdateBuilder {
    pub(crate) configuration_type_update: ::std::option::Option<crate::types::ConfigurationType>,
    pub(crate) checkpointing_enabled_update: ::std::option::Option<bool>,
    pub(crate) checkpoint_interval_update: ::std::option::Option<i64>,
    pub(crate) min_pause_between_checkpoints_update: ::std::option::Option<i64>,
}
impl CheckpointConfigurationUpdateBuilder {
    /// <p>Describes updates to whether the application uses the default checkpointing behavior of Managed Service for Apache Flink. You must set this property to <code>CUSTOM</code> in order to set the <code>CheckpointingEnabled</code>, <code>CheckpointInterval</code>, or <code>MinPauseBetweenCheckpoints</code> parameters.</p><note>
    /// <p>If this value is set to <code>DEFAULT</code>, the application will use the following values, even if they are set to other values using APIs or application code:</p>
    /// <ul>
    /// <li>
    /// <p><b>CheckpointingEnabled:</b> true</p></li>
    /// <li>
    /// <p><b>CheckpointInterval:</b> 60000</p></li>
    /// <li>
    /// <p><b>MinPauseBetweenCheckpoints:</b> 5000</p></li>
    /// </ul>
    /// </note>
    pub fn configuration_type_update(mut self, input: crate::types::ConfigurationType) -> Self {
        self.configuration_type_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes updates to whether the application uses the default checkpointing behavior of Managed Service for Apache Flink. You must set this property to <code>CUSTOM</code> in order to set the <code>CheckpointingEnabled</code>, <code>CheckpointInterval</code>, or <code>MinPauseBetweenCheckpoints</code> parameters.</p><note>
    /// <p>If this value is set to <code>DEFAULT</code>, the application will use the following values, even if they are set to other values using APIs or application code:</p>
    /// <ul>
    /// <li>
    /// <p><b>CheckpointingEnabled:</b> true</p></li>
    /// <li>
    /// <p><b>CheckpointInterval:</b> 60000</p></li>
    /// <li>
    /// <p><b>MinPauseBetweenCheckpoints:</b> 5000</p></li>
    /// </ul>
    /// </note>
    pub fn set_configuration_type_update(mut self, input: ::std::option::Option<crate::types::ConfigurationType>) -> Self {
        self.configuration_type_update = input;
        self
    }
    /// <p>Describes updates to whether the application uses the default checkpointing behavior of Managed Service for Apache Flink. You must set this property to <code>CUSTOM</code> in order to set the <code>CheckpointingEnabled</code>, <code>CheckpointInterval</code>, or <code>MinPauseBetweenCheckpoints</code> parameters.</p><note>
    /// <p>If this value is set to <code>DEFAULT</code>, the application will use the following values, even if they are set to other values using APIs or application code:</p>
    /// <ul>
    /// <li>
    /// <p><b>CheckpointingEnabled:</b> true</p></li>
    /// <li>
    /// <p><b>CheckpointInterval:</b> 60000</p></li>
    /// <li>
    /// <p><b>MinPauseBetweenCheckpoints:</b> 5000</p></li>
    /// </ul>
    /// </note>
    pub fn get_configuration_type_update(&self) -> &::std::option::Option<crate::types::ConfigurationType> {
        &self.configuration_type_update
    }
    /// <p>Describes updates to whether checkpointing is enabled for an application.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointingEnabled</code> value of <code>true</code>, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn checkpointing_enabled_update(mut self, input: bool) -> Self {
        self.checkpointing_enabled_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes updates to whether checkpointing is enabled for an application.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointingEnabled</code> value of <code>true</code>, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn set_checkpointing_enabled_update(mut self, input: ::std::option::Option<bool>) -> Self {
        self.checkpointing_enabled_update = input;
        self
    }
    /// <p>Describes updates to whether checkpointing is enabled for an application.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointingEnabled</code> value of <code>true</code>, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn get_checkpointing_enabled_update(&self) -> &::std::option::Option<bool> {
        &self.checkpointing_enabled_update
    }
    /// <p>Describes updates to the interval in milliseconds between checkpoint operations.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointInterval</code> value of 60000, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn checkpoint_interval_update(mut self, input: i64) -> Self {
        self.checkpoint_interval_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes updates to the interval in milliseconds between checkpoint operations.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointInterval</code> value of 60000, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn set_checkpoint_interval_update(mut self, input: ::std::option::Option<i64>) -> Self {
        self.checkpoint_interval_update = input;
        self
    }
    /// <p>Describes updates to the interval in milliseconds between checkpoint operations.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>CheckpointInterval</code> value of 60000, even if this value is set to another value using this API or in application code.</p>
    /// </note>
    pub fn get_checkpoint_interval_update(&self) -> &::std::option::Option<i64> {
        &self.checkpoint_interval_update
    }
    /// <p>Describes updates to the minimum time in milliseconds after a checkpoint operation completes that a new checkpoint operation can start.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>MinPauseBetweenCheckpoints</code> value of 5000, even if this value is set using this API or in application code.</p>
    /// </note>
    pub fn min_pause_between_checkpoints_update(mut self, input: i64) -> Self {
        self.min_pause_between_checkpoints_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes updates to the minimum time in milliseconds after a checkpoint operation completes that a new checkpoint operation can start.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>MinPauseBetweenCheckpoints</code> value of 5000, even if this value is set using this API or in application code.</p>
    /// </note>
    pub fn set_min_pause_between_checkpoints_update(mut self, input: ::std::option::Option<i64>) -> Self {
        self.min_pause_between_checkpoints_update = input;
        self
    }
    /// <p>Describes updates to the minimum time in milliseconds after a checkpoint operation completes that a new checkpoint operation can start.</p><note>
    /// <p>If <code>CheckpointConfiguration.ConfigurationType</code> is <code>DEFAULT</code>, the application will use a <code>MinPauseBetweenCheckpoints</code> value of 5000, even if this value is set using this API or in application code.</p>
    /// </note>
    pub fn get_min_pause_between_checkpoints_update(&self) -> &::std::option::Option<i64> {
        &self.min_pause_between_checkpoints_update
    }
    /// Consumes the builder and constructs a [`CheckpointConfigurationUpdate`](crate::types::CheckpointConfigurationUpdate).
    pub fn build(self) -> crate::types::CheckpointConfigurationUpdate {
        crate::types::CheckpointConfigurationUpdate {
            configuration_type_update: self.configuration_type_update,
            checkpointing_enabled_update: self.checkpointing_enabled_update,
            checkpoint_interval_update: self.checkpoint_interval_update,
            min_pause_between_checkpoints_update: self.min_pause_between_checkpoints_update,
        }
    }
}
