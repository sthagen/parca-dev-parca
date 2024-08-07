// Copyright 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import React, {useEffect, useRef, useState} from 'react';

import {Icon} from '@iconify/react';
import cx from 'classnames';

import {useParcaContext} from '@parca/components';

export interface SelectElement {
  active: JSX.Element;
  expanded: JSX.Element;
}

export interface SelectItem {
  key: string;
  disabled?: boolean;
  element: SelectElement;
}

interface CustomSelectProps {
  items: SelectItem[];
  selectedKey: string | undefined;
  onSelection: (value: string) => void;
  placeholder?: string;
  width?: number;
  className?: string;
  loading?: boolean;
  primary?: boolean;
  disabled?: boolean;
  icon?: JSX.Element;
  id?: string;
  optionsClassname?: string;
  searchable?: boolean;
  onButtonClick?: () => void;
}

const CustomSelect: React.FC<CustomSelectProps> = ({
  items,
  selectedKey,
  onSelection,
  placeholder,
  width,
  className = '',
  loading,
  primary = false,
  disabled = false,
  icon,
  id,
  optionsClassname = '',
  searchable = false,
  onButtonClick,
}) => {
  const {loader} = useParcaContext();
  const [isOpen, setIsOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const [searchTerm, setSearchTerm] = useState('');
  const containerRef = useRef<HTMLDivElement>(null);
  const optionsRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const optionRefs = useRef<Array<HTMLElement | null>>([]);

  const filteredItems = searchable
    ? items.filter(item =>
        item.element.active.props.children
          .toString()
          .toLowerCase()
          .includes(searchTerm.toLowerCase())
      )
    : items;

  const selection = items.find(v => v.key === selectedKey);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent): void => {
      if (containerRef.current !== null && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  useEffect(() => {
    if (isOpen && searchable) {
      searchInputRef.current?.focus();
    }
  }, [isOpen, searchable]);

  useEffect(() => {
    if (
      focusedIndex !== -1 &&
      optionsRef.current !== null &&
      optionRefs.current[focusedIndex] !== null
    ) {
      const optionElement = optionRefs.current[focusedIndex];
      const optionsContainer = optionsRef.current;

      if (optionElement !== null && optionsContainer !== null) {
        const optionRect = optionElement.getBoundingClientRect();
        const containerRect = optionsContainer.getBoundingClientRect();

        if (optionRect.bottom > containerRect.bottom) {
          optionsContainer.scrollTop += optionRect.bottom - containerRect.bottom;
        } else if (optionRect.top < containerRect.top) {
          optionsContainer.scrollTop -= containerRect.top - optionRect.top;
        }
      }
    }
  }, [focusedIndex]);

  const handleKeyDown = (e: React.KeyboardEvent): void => {
    if (e.key === 'Enter') {
      if (!isOpen) {
        setIsOpen(true);
      } else if (focusedIndex !== -1) {
        onSelection(filteredItems[focusedIndex].key);
        setIsOpen(false);
      }
    } else if (e.key === 'Escape') {
      setIsOpen(false);
    } else if (e.key === 'Tab') {
      if (isOpen) {
        e.preventDefault();
        if (e.shiftKey) {
          // Shift+Tab: Move focus to the previous item
          setFocusedIndex(prevIndex => (prevIndex <= 0 ? filteredItems.length - 1 : prevIndex - 1));
        } else {
          // Tab: Move focus to the next item
          setFocusedIndex(prevIndex => (prevIndex + 1) % filteredItems.length);
        }
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setFocusedIndex(prevIndex => (prevIndex + 1) % filteredItems.length);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setFocusedIndex(prevIndex => (prevIndex - 1 + filteredItems.length) % filteredItems.length);
    }
  };

  const styles =
    'relative border rounded-md shadow-sm px-4 py-2 text-left cursor-default focus:outline-none focus:ring-1 items-center focus:ring-indigo-500 focus:border-indigo-500 text-sm flex gap-2 flex items-center justify-between';
  const defaultStyles = 'bg-white dark:bg-gray-900 dark:border-gray-600';
  const primaryStyles =
    'text-gray-100 dark:gray-900 bg-indigo-600 border-indigo-500 font-medium py-2 px-4';

  return (
    <div ref={containerRef} className="relative" onKeyDown={handleKeyDown} onClick={onButtonClick}>
      <div
        id={id}
        onClick={() => !disabled && setIsOpen(!isOpen)}
        className={cx(
          styles,
          width !== undefined ? `w-${width}` : 'w-full',
          disabled ? 'cursor-not-allowed opacity-50 pointer-events-none' : '',
          primary ? primaryStyles : defaultStyles,
          {[className]: className.length > 0}
        )}
        tabIndex={0}
        role="button"
        aria-haspopup="listbox"
        aria-expanded={isOpen}
      >
        <div
          className={cx(
            icon != null ? '' : 'block overflow-x-hidden text-ellipsis whitespace-nowrap'
          )}
        >
          {selection?.element.active ?? placeholder}
        </div>
        <div className={cx(icon != null ? '' : 'pointer-events-none text-gray-400')}>
          {icon ?? <Icon icon="heroicons:chevron-up-down-20-solid" aria-hidden="true" />}
        </div>
      </div>

      {isOpen && (
        <div
          ref={optionsRef}
          className={cx(
            'absolute z-50 mt-1 pt-0 max-h-[50vh] w-max overflow-auto rounded-md bg-gray-50 py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none dark:border-gray-600 dark:bg-gray-900 dark:ring-white dark:ring-opacity-20 sm:text-sm',
            {[optionsClassname]: optionsClassname.length > 0}
          )}
          role="listbox"
        >
          {searchable && (
            <div className="sticky h-[45px] z-10 top-[-5px] border-b border-gray-200">
              <input
                ref={searchInputRef}
                type="text"
                className="w-full px-6 h-full text-sm border-none rounded-none ring-0 outline-none bg-gray-50 dark:bg-gray-800 dark:text-white"
                placeholder="Search..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
              />
            </div>
          )}
          {loading === true ? (
            <div className="w-[270px]">{loader}</div>
          ) : (
            filteredItems.map((item, index) => (
              <div
                key={item.key}
                ref={el => (optionRefs.current[index] = el)}
                className={cx(
                  'relative cursor-default select-none py-2 pl-3 pr-9',
                  index === focusedIndex && 'bg-indigo-600 text-white',
                  item.key === selectedKey && 'bg-indigo-100 dark:bg-indigo-700',
                  item.disabled !== null &&
                    item.disabled === true &&
                    'opacity-50 cursor-not-allowed',
                  'focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 hover:bg-indigo-600 hover:text-white'
                )}
                role="option"
                aria-selected={item.key === selectedKey}
                tabIndex={-1}
                onClick={() => {
                  if (!(item.disabled ?? false)) {
                    onSelection(item.key);
                    setIsOpen(false);
                  }
                }}
              >
                {item.element.expanded}
                {item.key === selectedKey && (
                  <span className="absolute inset-y-0 right-0 flex items-center pr-4 text-indigo-600">
                    <Icon icon="heroicons:check-20-solid" aria-hidden="true" />
                  </span>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

export default CustomSelect;