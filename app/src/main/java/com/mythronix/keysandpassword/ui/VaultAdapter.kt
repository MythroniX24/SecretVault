package com.mythronix.keysandpassword.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.mythronix.keysandpassword.R
import com.mythronix.keysandpassword.databinding.ItemVaultBinding
import com.mythronix.keysandpassword.models.VaultItem

class VaultAdapter(
    private val onItemClick: (VaultItem) -> Unit,
    private val onItemLongClick: (VaultItem) -> Unit
) : ListAdapter<VaultItem, VaultAdapter.VaultViewHolder>(DIFF_CALLBACK) {

    inner class VaultViewHolder(private val binding: ItemVaultBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(item: VaultItem) {
            binding.tvItemName.text = item.name

            if (item.type == VaultItem.TYPE_PASSWORD) {
                binding.ivItemIcon.setImageResource(R.drawable.ic_lock)
                binding.chipType.text = "Password"
            } else {
                binding.ivItemIcon.setImageResource(R.drawable.ic_key)
                binding.chipType.text = "API Token"
            }

            binding.root.setOnClickListener { onItemClick(item) }
            binding.root.setOnLongClickListener { onItemLongClick(item); true }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VaultViewHolder(
            ItemVaultBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        )

    override fun onBindViewHolder(holder: VaultViewHolder, position: Int) =
        holder.bind(getItem(position))

    companion object {
        private val DIFF_CALLBACK = object : DiffUtil.ItemCallback<VaultItem>() {
            override fun areItemsTheSame(old: VaultItem, new: VaultItem) = old.id == new.id
            override fun areContentsTheSame(old: VaultItem, new: VaultItem) = old == new
        }
    }
}
