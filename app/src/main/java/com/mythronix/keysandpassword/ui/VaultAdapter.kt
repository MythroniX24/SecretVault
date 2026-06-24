package com.mythronix.keysandpassword.ui

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.widget.ImageViewCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.color.MaterialColors
import com.mythronix.keysandpassword.R
import com.mythronix.keysandpassword.databinding.ItemVaultBinding
import com.mythronix.keysandpassword.models.VaultItem

class VaultAdapter(
    private val onItemClick: (VaultItem) -> Unit,
    private val onItemLongClick: (VaultItem) -> Unit,
    private val onFavoriteClick: (VaultItem) -> Unit
) : ListAdapter<VaultItem, VaultAdapter.VaultViewHolder>(DIFF_CALLBACK) {

    private var allItems: List<VaultItem> = emptyList()

    fun submitFullList(items: List<VaultItem>) {
        allItems = items
        submitList(getSortedItems(items))
    }

    /** Sort: favorites first, then by createdAt descending */
    private fun getSortedItems(items: List<VaultItem>): List<VaultItem> {
        return items.sortedByDescending { it.isFavorite }
            .let { sorted ->
                // Within each group, sort by createdAt
                sorted.sortedWith(compareByDescending<VaultItem> { it.isFavorite }.thenByDescending { it.createdAt })
            }
    }

    inner class VaultViewHolder(private val binding: ItemVaultBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(item: VaultItem) {
            binding.tvItemName.text = item.name

            if (item.type == VaultItem.TYPE_PASSWORD) {
                binding.ivItemIcon.setImageResource(R.drawable.ic_lock)
                binding.chipType.text = "Password"
            } else {
                binding.ivItemIcon.setImageResource(R.drawable.ic_key)
                binding.chipType.text = "Token"
            }

            // Category label
            binding.tvCategory.text = when (item.category) {
                VaultItem.CATEGORY_UNCATEGORIZED -> ""
                else -> "· ${item.category}"
            }

            // Favorite star
            if (item.isFavorite) {
                binding.ivFavorite.alpha = 1.0f
                ImageViewCompat.setImageTintList(binding.ivFavorite, null) // show gold color
            } else {
                binding.ivFavorite.alpha = 0.25f
                val color = MaterialColors.getColor(binding.ivFavorite, com.google.android.material.R.attr.colorOnSurfaceVariant)
                ImageViewCompat.setImageTintList(binding.ivFavorite, android.content.res.ColorStateList.valueOf(color))
            }

            binding.root.setOnClickListener { onItemClick(item) }
            binding.root.setOnLongClickListener { onItemLongClick(item); true }
            binding.ivFavorite.setOnClickListener { onFavoriteClick(item) }
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
