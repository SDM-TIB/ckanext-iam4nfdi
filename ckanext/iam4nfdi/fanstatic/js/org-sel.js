/*document.addEventListener('DOMContentLoaded', function () {
  const itemsList = document.getElementById('org-list');

  itemsList.classList.add('scrollable-list');

  const checkboxes = document.querySelectorAll('input[type="checkbox"]');
  checkboxes.forEach((checkbox) => {
    checkbox.addEventListener('change', (e) => {
      if (e.target.checked) {
        const item = document.createElement('li');
        item.innerHTML = e.target.id;
        itemsList.appendChild(item);
      } else {
        const itemToRemove = itemsList.querySelector(`li#${e.target.id}`);
        if (itemToRemove) {
          itemToRemove.remove();
        }
      }
    });
  });
});*/
